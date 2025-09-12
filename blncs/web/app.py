#!/usr/bin/env python3
"""
BLNCS Web Dashboard Application
Flask-based web interface for BLNCS management.
"""

import os
import json
from pathlib import Path
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory
from flask_socketio import SocketIO, emit
from typing import Dict, Any, Optional
import logging
from datetime import datetime, timedelta
import secrets

from .api_client import BLNCSAPIClient
from .dashboard_routes import dashboard_routes
from .static_routes import static_routes
from .websocket_handler import WebSocketHandler

logger = logging.getLogger(__name__)

class WebDashboardServer:
    """BLNCS Web Dashboard Server"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.app = None
        self.socketio = None
        self.api_client = None
        self.websocket_handler = None
        
        # Default configuration
        self.default_config = {
            'host': '0.0.0.0',
            'port': 3000,
            'debug': False,
            'api_url': 'http://localhost:8080',
            'api_key': None,
            'session_timeout_hours': 24,
            'theme': 'light',
            'auto_refresh_interval': 30,
            'max_log_entries': 1000
        }
        
        # Merge with user config
        self.config = {**self.default_config, **self.config}
        
        # Paths
        self.template_dir = Path(__file__).parent / 'templates'
        self.static_dir = Path(__file__).parent / 'static'
        
        # Create directories if they don't exist
        self.template_dir.mkdir(exist_ok=True)
        self.static_dir.mkdir(exist_ok=True)
    
    def create_app(self) -> Flask:
        """Create Flask application"""
        self.app = Flask(__name__,
                        template_folder=str(self.template_dir),
                        static_folder=str(self.static_dir))
        
        # Configure Flask
        self.app.config.update({
            'SECRET_KEY': secrets.token_hex(32),
            'PERMANENT_SESSION_LIFETIME': timedelta(hours=self.config['session_timeout_hours']),
            'WTF_CSRF_ENABLED': True,
            'WTF_CSRF_TIME_LIMIT': 3600
        })
        
        # Initialize SocketIO
        self.socketio = SocketIO(self.app, 
                               cors_allowed_origins="*",
                               async_mode='threading',
                               logger=False,
                               engineio_logger=False)
        
        # Initialize API client
        self.api_client = BLNCSAPIClient(
            base_url=self.config['api_url'],
            api_key=self.config.get('api_key')
        )
        
        # Initialize WebSocket handler
        self.websocket_handler = WebSocketHandler(self.socketio, self.api_client)
        
        # Register routes
        self._register_routes()
        self._register_error_handlers()
        self._register_template_filters()
        
        return self.app
    
    def _register_routes(self):
        """Register all application routes"""
        
        # Main dashboard route
        @self.app.route('/')
        def index():
            return render_template('dashboard.html', 
                                 config=self.config,
                                 current_page='dashboard')
        
        # Authentication routes
        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            if request.method == 'POST':
                api_key = request.json.get('api_key')
                
                if not api_key:
                    return jsonify({'success': False, 'error': 'API key required'}), 400
                
                # Verify API key with backend
                test_client = BLNCSAPIClient(self.config['api_url'], api_key)
                if test_client.test_connection():
                    session['api_key'] = api_key
                    session['authenticated'] = True
                    session.permanent = True
                    
                    # Update global API client
                    self.api_client.api_key = api_key
                    
                    return jsonify({'success': True, 'redirect': url_for('index')})
                else:
                    return jsonify({'success': False, 'error': 'Invalid API key'}), 401
            
            return render_template('login.html')
        
        @self.app.route('/logout')
        def logout():
            session.clear()
            return redirect(url_for('login'))
        
        # Dashboard API routes
        @self.app.route('/api/dashboard/status')
        def dashboard_status():
            if not self._is_authenticated():
                return jsonify({'error': 'Authentication required'}), 401
            
            try:
                # Get system status from API
                status = self.api_client.get_system_status()
                metrics = self.api_client.get_metrics()
                
                return jsonify({
                    'success': True,
                    'status': status,
                    'metrics': metrics,
                    'timestamp': datetime.now().isoformat()
                })
            except Exception as e:
                logger.error(f"Failed to get dashboard status: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500
        
        @self.app.route('/api/dashboard/backups')
        def dashboard_backups():
            if not self._is_authenticated():
                return jsonify({'error': 'Authentication required'}), 401
            
            try:
                backups = self.api_client.get_backup_list()
                return jsonify({'success': True, 'backups': backups})
            except Exception as e:
                logger.error(f"Failed to get backups: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500
        
        @self.app.route('/api/dashboard/schedules')
        def dashboard_schedules():
            if not self._is_authenticated():
                return jsonify({'error': 'Authentication required'}), 401
            
            try:
                schedules = self.api_client.get_schedules()
                return jsonify({'success': True, 'schedules': schedules})
            except Exception as e:
                logger.error(f"Failed to get schedules: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500
        
        # Backup management routes
        @self.app.route('/backups')
        def backups():
            return render_template('backups.html', 
                                 config=self.config,
                                 current_page='backups')
        
        @self.app.route('/api/backup/create', methods=['POST'])
        def create_backup():
            if not self._is_authenticated():
                return jsonify({'error': 'Authentication required'}), 401
            
            try:
                data = request.get_json()
                result = self.api_client.create_backup(data)
                return jsonify(result)
            except Exception as e:
                logger.error(f"Failed to create backup: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500
        
        # Schedule management routes
        @self.app.route('/schedules')
        def schedules():
            return render_template('schedules.html',
                                 config=self.config, 
                                 current_page='schedules')
        
        @self.app.route('/api/schedule/create', methods=['POST'])
        def create_schedule():
            if not self._is_authenticated():
                return jsonify({'error': 'Authentication required'}), 401
            
            try:
                data = request.get_json()
                result = self.api_client.create_schedule(data)
                return jsonify(result)
            except Exception as e:
                logger.error(f"Failed to create schedule: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500
        
        # Monitoring routes
        @self.app.route('/monitoring')
        def monitoring():
            return render_template('monitoring.html',
                                 config=self.config,
                                 current_page='monitoring')
        
        @self.app.route('/api/monitoring/metrics')
        def monitoring_metrics():
            if not self._is_authenticated():
                return jsonify({'error': 'Authentication required'}), 401
            
            try:
                metrics = self.api_client.get_detailed_metrics()
                return jsonify({'success': True, 'metrics': metrics})
            except Exception as e:
                logger.error(f"Failed to get metrics: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500
        
        # Settings routes
        @self.app.route('/settings')
        def settings():
            return render_template('settings.html',
                                 config=self.config,
                                 current_page='settings')
        
        @self.app.route('/api/settings/update', methods=['POST'])
        def update_settings():
            if not self._is_authenticated():
                return jsonify({'error': 'Authentication required'}), 401
            
            try:
                data = request.get_json()
                # Update dashboard configuration
                for key in ['theme', 'auto_refresh_interval', 'max_log_entries']:
                    if key in data:
                        self.config[key] = data[key]
                
                return jsonify({'success': True, 'message': 'Settings updated'})
            except Exception as e:
                logger.error(f"Failed to update settings: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500
        
        # Recovery routes
        @self.app.route('/recovery')
        def recovery():
            return render_template('recovery.html',
                                 config=self.config,
                                 current_page='recovery')
        
        @self.app.route('/api/recovery/execute', methods=['POST'])
        def execute_recovery():
            if not self._is_authenticated():
                return jsonify({'error': 'Authentication required'}), 401
            
            try:
                data = request.get_json()
                result = self.api_client.execute_recovery(data)
                return jsonify(result)
            except Exception as e:
                logger.error(f"Failed to execute recovery: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500
        
        # Health check
        @self.app.route('/health')
        def health():
            try:
                # Check API connectivity
                api_healthy = self.api_client.test_connection()
                
                status = {
                    'status': 'healthy' if api_healthy else 'unhealthy',
                    'timestamp': datetime.now().isoformat(),
                    'components': {
                        'web_server': 'healthy',
                        'api_connection': 'healthy' if api_healthy else 'unhealthy'
                    }
                }
                
                status_code = 200 if api_healthy else 503
                return jsonify(status), status_code
            except Exception as e:
                return jsonify({
                    'status': 'unhealthy',
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                }), 503
        
        # Static file serving
        @self.app.route('/favicon.ico')
        def favicon():
            return send_from_directory(self.static_dir, 'favicon.ico')
    
    def _register_error_handlers(self):
        """Register error handlers"""
        
        @self.app.errorhandler(404)
        def not_found(error):
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Not found'}), 404
            return render_template('error.html', 
                                 error_code=404,
                                 error_message='Page not found'), 404
        
        @self.app.errorhandler(500)
        def internal_error(error):
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Internal server error'}), 500
            return render_template('error.html',
                                 error_code=500,
                                 error_message='Internal server error'), 500
        
        @self.app.before_request
        def check_authentication():
            # Skip authentication for static files and auth routes
            if (request.endpoint in ['login', 'health', 'static', 'favicon'] or
                request.path.startswith('/static/')):
                return
            
            # Check if authenticated for protected routes
            if not self._is_authenticated() and request.endpoint != 'login':
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Authentication required'}), 401
                return redirect(url_for('login'))
    
    def _register_template_filters(self):
        """Register custom template filters"""
        
        @self.app.template_filter('datetime_format')
        def datetime_format(value):
            if isinstance(value, str):
                try:
                    value = datetime.fromisoformat(value.replace('Z', '+00:00'))
                except:
                    return value
            return value.strftime('%Y-%m-%d %H:%M:%S') if value else ''
        
        @self.app.template_filter('file_size')
        def file_size_format(size_bytes):
            if not size_bytes:
                return '0 B'
            
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if size_bytes < 1024.0:
                    return f"{size_bytes:.1f} {unit}"
                size_bytes /= 1024.0
            return f"{size_bytes:.1f} PB"
        
        @self.app.template_filter('duration')
        def duration_format(seconds):
            if not seconds:
                return '0s'
            
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            seconds = int(seconds % 60)
            
            parts = []
            if hours > 0:
                parts.append(f"{hours}h")
            if minutes > 0:
                parts.append(f"{minutes}m")
            if seconds > 0 or not parts:
                parts.append(f"{seconds}s")
            
            return ' '.join(parts)
        
        @self.app.context_processor
        def inject_globals():
            return {
                'now': datetime.now(),
                'version': '2.0.0',
                'config': self.config
            }
    
    def _is_authenticated(self) -> bool:
        """Check if user is authenticated"""
        return session.get('authenticated', False) and session.get('api_key')
    
    def run(self):
        """Run the web dashboard server"""
        if not self.app:
            self.create_app()
        
        logger.info(f"Starting BLNCS Web Dashboard on {self.config['host']}:{self.config['port']}")
        
        self.socketio.run(
            self.app,
            host=self.config['host'],
            port=self.config['port'],
            debug=self.config['debug'],
            use_reloader=False  # Disable reloader when using SocketIO
        )

def create_web_app(config: Dict[str, Any] = None) -> Flask:
    """Factory function to create Flask app"""
    server = WebDashboardServer(config)
    return server.create_app()