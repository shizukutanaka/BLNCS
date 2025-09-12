#!/usr/bin/env python3
"""
BLNCS API Application
Main Flask application with comprehensive REST API endpoints for Lightning Network management.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
import threading
from datetime import datetime
from typing import Dict, Any, Optional

from .auth import AuthManager, api_key_required, rate_limit
from .responses import success_response, error_response
from .validators import validate_request, RequestValidator
from .middleware import setup_middleware
from .endpoints import register_api_endpoints

# Import system components
try:
    from ..backup import get_backup_manager, get_recovery_engine, get_backup_scheduler
    from ..core.config_manager import get_config_manager
    from ..core.health import get_health_manager
    from ..monitoring.production_monitor import get_production_monitor
    from ..i18n import get_translator
    COMPONENTS_AVAILABLE = True
except ImportError:
    COMPONENTS_AVAILABLE = False

logger = logging.getLogger(__name__)

class BLNCSAPIServer:
    """BLNCS REST API Server with comprehensive Lightning Network management endpoints"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.app = None
        self.auth_manager = None
        self.server_thread = None
        self.running = False
        
        # Component managers
        self.backup_manager = None
        self.recovery_engine = None
        self.scheduler = None
        self.config_manager = None
        self.health_manager = None
        self.monitor = None
        self.translator = None
        
        self._initialize_components()
        self._create_app()
    
    def _initialize_components(self):
        """Initialize system components"""
        if not COMPONENTS_AVAILABLE:
            logger.warning("Some system components not available")
            return
            
        try:
            self.backup_manager = get_backup_manager()
            self.recovery_engine = get_recovery_engine()
            self.scheduler = get_backup_scheduler()
            self.config_manager = get_config_manager()
            self.health_manager = get_health_manager()
            self.monitor = get_production_monitor()
            self.translator = get_translator()
            
        except Exception as e:
            logger.error(f"Failed to initialize components: {e}")
    
    def _create_app(self):
        """Create and configure Flask application"""
        self.app = Flask(__name__)
        
        # Configuration
        self.app.config.update({
            'SECRET_KEY': self.config.get('secret_key', 'dev-secret-key'),
            'API_VERSION': '2.0.0',
            'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,  # 16MB max upload
            'JSON_SORT_KEYS': False
        })
        
        # CORS configuration
        cors_config = self.config.get('cors', {})
        CORS(self.app, 
             origins=cors_config.get('origins', ['http://localhost:3000']),
             supports_credentials=True)
        
        # Authentication
        self.auth_manager = AuthManager(self.config.get('auth', {}))
        
        # Middleware
        setup_middleware(self.app)
        
        # Register endpoints
        self._register_endpoints()
        
        # Error handlers
        self._register_error_handlers()
        
        logger.info("BLNCS API Server initialized")
    
    def _register_endpoints(self):
        """Register all API endpoints"""
        
        # Health check endpoint
        @self.app.route('/health', methods=['GET'])
        def health_check():
            """System health check endpoint"""
            try:
                status = {
                    'status': 'healthy',
                    'timestamp': datetime.now().isoformat(),
                    'version': self.app.config['API_VERSION'],
                    'components': {}
                }
                
                if self.health_manager:
                    health_results = self.health_manager.check_all_health()
                    status['components'] = {
                        name: 'healthy' if result.healthy else 'unhealthy'
                        for name, result in health_results.items()
                    }
                    overall_health = all(result.healthy for result in health_results.values())
                    status['status'] = 'healthy' if overall_health else 'degraded'
                
                return success_response(status)
                
            except Exception as e:
                return error_response(f"Health check failed: {str(e)}", 500)
        
        # API info endpoint
        @self.app.route('/api/v1', methods=['GET'])
        def api_info():
            """API information endpoint"""
            return success_response({
                'name': 'BLNCS API',
                'version': self.app.config['API_VERSION'],
                'description': 'Bitcoin Lightning Network Control System REST API',
                'documentation': '/api/v1/docs',
                'endpoints': {
                    'health': '/health',
                    'backup': '/api/v1/backup',
                    'recovery': '/api/v1/recovery',
                    'schedule': '/api/v1/schedule',
                    'config': '/api/v1/config',
                    'monitor': '/api/v1/monitor',
                    'node': '/api/v1/node'
                }
            })
        
        # System status endpoint
        @self.app.route('/api/v1/status', methods=['GET'])
        @api_key_required
        def system_status():
            """Comprehensive system status"""
            try:
                status = {
                    'timestamp': datetime.now().isoformat(),
                    'uptime': getattr(self, 'start_time', datetime.now()).isoformat(),
                    'components': {},
                    'metrics': {},
                    'alerts': []
                }
                
                # Backup system status
                if self.backup_manager:
                    backup_stats = self.backup_manager.get_statistics()
                    status['components']['backup'] = {
                        'status': 'active',
                        'statistics': backup_stats
                    }
                
                # Scheduler status
                if self.scheduler:
                    scheduler_stats = self.scheduler.get_statistics()
                    status['components']['scheduler'] = {
                        'status': 'running' if scheduler_stats.get('scheduler_running') else 'stopped',
                        'statistics': scheduler_stats
                    }
                
                # Monitor status
                if self.monitor:
                    try:
                        monitor_status = self.monitor.get_system_metrics()
                        status['components']['monitor'] = {
                            'status': 'active',
                            'metrics': monitor_status
                        }
                    except Exception as e:
                        status['components']['monitor'] = {
                            'status': 'error',
                            'error': str(e)
                        }
                
                return success_response(status)
                
            except Exception as e:
                return error_response(f"Failed to get system status: {str(e)}", 500)
        
        # Register specialized endpoint groups
        register_api_endpoints(self.app, {
            'backup_manager': self.backup_manager,
            'recovery_engine': self.recovery_engine,
            'scheduler': self.scheduler,
            'config_manager': self.config_manager,
            'health_manager': self.health_manager,
            'monitor': self.monitor,
            'translator': self.translator,
            'auth_manager': self.auth_manager
        })
    
    def _register_error_handlers(self):
        """Register global error handlers"""
        
        @self.app.errorhandler(400)
        def bad_request(error):
            return error_response("Bad request", 400)
        
        @self.app.errorhandler(401)
        def unauthorized(error):
            return error_response("Unauthorized", 401)
        
        @self.app.errorhandler(403)
        def forbidden(error):
            return error_response("Forbidden", 403)
        
        @self.app.errorhandler(404)
        def not_found(error):
            return error_response("Resource not found", 404)
        
        @self.app.errorhandler(429)
        def rate_limit_exceeded(error):
            return error_response("Rate limit exceeded", 429)
        
        @self.app.errorhandler(500)
        def internal_error(error):
            logger.error(f"Internal server error: {error}")
            return error_response("Internal server error", 500)
        
        @self.app.errorhandler(Exception)
        def handle_exception(e):
            logger.error(f"Unhandled exception: {e}", exc_info=True)
            return error_response(f"Internal server error: {str(e)}", 500)
    
    def start(self, host: str = '0.0.0.0', port: int = 9090, debug: bool = False):
        """Start the API server"""
        try:
            self.start_time = datetime.now()
            
            if debug:
                # Development mode
                self.app.run(host=host, port=port, debug=True)
            else:
                # Production mode with threading
                from wsgiref.simple_server import make_server
                
                self.server = make_server(host, port, self.app)
                self.server_thread = threading.Thread(
                    target=self.server.serve_forever,
                    daemon=True
                )
                self.server_thread.start()
                self.running = True
                
                logger.info(f"BLNCS API Server started on http://{host}:{port}")
                
        except Exception as e:
            logger.error(f"Failed to start API server: {e}")
            raise
    
    def stop(self):
        """Stop the API server"""
        try:
            if hasattr(self, 'server') and self.server:
                self.server.shutdown()
                self.running = False
                logger.info("API server stopped")
                
        except Exception as e:
            logger.error(f"Error stopping API server: {e}")
    
    def is_running(self) -> bool:
        """Check if server is running"""
        return self.running

def create_app(config: Optional[Dict[str, Any]] = None) -> Flask:
    """Create Flask application"""
    server = BLNCSAPIServer(config)
    return server.app

def create_api_server(config: Optional[Dict[str, Any]] = None) -> BLNCSAPIServer:
    """Create BLNCS API server instance"""
    return BLNCSAPIServer(config)

# Global server instance
_api_server = None

def get_api_server(config: Optional[Dict[str, Any]] = None) -> BLNCSAPIServer:
    """Get global API server instance"""
    global _api_server
    if _api_server is None:
        _api_server = create_api_server(config)
    return _api_server