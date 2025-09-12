#!/usr/bin/env python3
"""
BLNCS API Middleware
Comprehensive middleware stack for request processing, logging, and security.
"""

from flask import request, g, current_app
import time
import uuid
from datetime import datetime
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

def request_id_middleware(app):
    """Add unique request ID to each request"""
    
    @app.before_request
    def add_request_id():
        g.request_id = request.headers.get('X-Request-ID') or str(uuid.uuid4())
        g.request_start_time = time.time()
    
    @app.after_request
    def add_request_id_header(response):
        if hasattr(g, 'request_id'):
            response.headers['X-Request-ID'] = g.request_id
        return response

def logging_middleware(app):
    """Comprehensive request logging"""
    
    @app.before_request
    def log_request_start():
        logger.info(f"Request started: {request.method} {request.path}", extra={
            'request_id': getattr(g, 'request_id', 'unknown'),
            'method': request.method,
            'path': request.path,
            'remote_addr': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'content_length': request.content_length
        })
    
    @app.after_request
    def log_request_end(response):
        duration = time.time() - getattr(g, 'request_start_time', time.time())
        
        logger.info(f"Request completed: {response.status_code}", extra={
            'request_id': getattr(g, 'request_id', 'unknown'),
            'status_code': response.status_code,
            'duration_ms': round(duration * 1000, 2),
            'response_length': response.content_length
        })
        
        return response

def cors_middleware(app):
    """CORS handling middleware"""
    
    @app.after_request
    def add_cors_headers(response):
        # Get CORS configuration
        cors_config = getattr(app, 'cors_config', {})
        
        # Add CORS headers
        origin = request.headers.get('Origin')
        allowed_origins = cors_config.get('origins', ['*'])
        
        if '*' in allowed_origins or origin in allowed_origins:
            response.headers['Access-Control-Allow-Origin'] = origin or '*'
        
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-API-Key, X-Request-ID'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Max-Age'] = '86400'
        
        return response
    
    @app.before_request
    def handle_preflight():
        if request.method == 'OPTIONS':
            response = current_app.make_default_options_response()
            return response

def security_middleware(app):
    """Security headers and protections"""
    
    @app.after_request
    def add_security_headers(response):
        # Security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Content Security Policy
        csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
        response.headers['Content-Security-Policy'] = csp
        
        return response

def rate_limiting_middleware(app):
    """Rate limiting enforcement"""
    
    @app.before_request
    def enforce_rate_limits():
        # Get auth manager
        auth_manager = getattr(app, 'auth_manager', None)
        if not auth_manager:
            return
        
        # Check API key
        api_key_info = None
        try:
            api_key_info = auth_manager.authenticate_request(request)
        except:
            pass
        
        # Check rate limits
        allowed, rate_info = auth_manager.check_rate_limit(request, api_key_info)
        
        if not allowed:
            from .responses import rate_limit_response
            return rate_limit_response(rate_info['limit'], rate_info['reset_time'])
        
        # Store rate limit info
        g.rate_limit_info = rate_info

def error_handling_middleware(app):
    """Global error handling"""
    
    @app.errorhandler(Exception)
    def handle_exception(e):
        logger.error(f"Unhandled exception in request {getattr(g, 'request_id', 'unknown')}: {e}", 
                    exc_info=True)
        
        from .responses import server_error_response
        return server_error_response("An unexpected error occurred")

def performance_monitoring_middleware(app):
    """Performance monitoring and metrics"""
    
    @app.before_request
    def start_performance_monitoring():
        g.performance_start = time.time()
        g.performance_metrics = {
            'endpoint': f"{request.method} {request.path}",
            'start_time': datetime.now().isoformat()
        }
    
    @app.after_request
    def record_performance_metrics(response):
        if hasattr(g, 'performance_start'):
            duration = time.time() - g.performance_start
            
            # Record metrics
            metrics = {
                'duration_ms': round(duration * 1000, 2),
                'status_code': response.status_code,
                'request_size': request.content_length or 0,
                'response_size': response.content_length or 0,
                'endpoint': g.performance_metrics.get('endpoint'),
                'request_id': getattr(g, 'request_id', 'unknown')
            }
            
            # Log performance metrics
            logger.debug(f"Performance metrics", extra=metrics)
            
            # Add performance headers
            response.headers['X-Response-Time'] = str(round(duration * 1000, 2))
        
        return response

def authentication_middleware(app):
    """Authentication processing"""
    
    @app.before_request
    def process_authentication():
        # Skip authentication for certain endpoints
        exempt_endpoints = ['/health', '/api/v1', '/api/v1/docs']
        
        if request.path in exempt_endpoints or request.method == 'OPTIONS':
            return
        
        # Get auth manager
        auth_manager = getattr(app, 'auth_manager', None)
        if not auth_manager:
            return
        
        # Authenticate request
        api_key_info = auth_manager.authenticate_request(request)
        
        # Store authentication info
        g.api_key_info = api_key_info
        g.authenticated = api_key_info is not None

def request_validation_middleware(app):
    """Request validation and sanitization"""
    
    @app.before_request
    def validate_request_data():
        # Skip validation for GET requests
        if request.method == 'GET' or request.method == 'OPTIONS':
            return
        
        # Validate content type for POST/PUT requests
        if request.method in ['POST', 'PUT', 'PATCH']:
            if not request.is_json and not request.form:
                from .responses import error_response
                return error_response("Content-Type must be application/json or form data", 400)
        
        # Validate request size
        max_size = app.config.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024)
        if request.content_length and request.content_length > max_size:
            from .responses import error_response
            return error_response("Request too large", 413)

def response_formatting_middleware(app):
    """Standardize response formatting"""
    
    @app.after_request
    def format_response(response):
        # Add standard API headers
        response.headers['X-API-Version'] = app.config.get('API_VERSION', '2.0.0')
        response.headers['X-Timestamp'] = datetime.now().isoformat()
        
        # Ensure JSON content type for API responses
        if response.content_type and 'application/json' in response.content_type:
            response.headers['Content-Type'] = 'application/json; charset=utf-8'
        
        return response

def maintenance_mode_middleware(app):
    """Handle maintenance mode"""
    
    @app.before_request
    def check_maintenance_mode():
        # Check if maintenance mode is enabled
        maintenance_config = getattr(app, 'maintenance_config', {})
        
        if maintenance_config.get('enabled', False):
            # Allow certain endpoints during maintenance
            allowed_endpoints = ['/health', '/api/v1/status']
            
            if request.path not in allowed_endpoints:
                from .responses import error_response
                message = maintenance_config.get('message', 'System under maintenance')
                return error_response(message, 503)

def setup_middleware(app):
    """Setup all middleware components"""
    
    # Store auth manager reference for middleware
    if hasattr(app, 'auth_manager'):
        app.auth_manager = app.auth_manager
    
    # Apply middleware in order
    request_id_middleware(app)
    logging_middleware(app)
    cors_middleware(app)
    security_middleware(app)
    maintenance_mode_middleware(app)
    request_validation_middleware(app)
    authentication_middleware(app)
    rate_limiting_middleware(app)
    performance_monitoring_middleware(app)
    response_formatting_middleware(app)
    error_handling_middleware(app)
    
    logger.info("API middleware stack initialized")

class MiddlewareManager:
    """Manage middleware configuration and state"""
    
    def __init__(self, app=None):
        self.app = app
        self.middleware_config = {}
        self.middleware_stats = {
            'requests_processed': 0,
            'errors_handled': 0,
            'rate_limited': 0,
            'authenticated_requests': 0
        }
    
    def configure_cors(self, origins=None, methods=None, headers=None):
        """Configure CORS settings"""
        self.middleware_config['cors'] = {
            'origins': origins or ['*'],
            'methods': methods or ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
            'headers': headers or ['Content-Type', 'Authorization', 'X-API-Key']
        }
        
        if self.app:
            self.app.cors_config = self.middleware_config['cors']
    
    def configure_maintenance(self, enabled=False, message=None):
        """Configure maintenance mode"""
        self.middleware_config['maintenance'] = {
            'enabled': enabled,
            'message': message or 'System under maintenance'
        }
        
        if self.app:
            self.app.maintenance_config = self.middleware_config['maintenance']
    
    def get_stats(self) -> Dict[str, Any]:
        """Get middleware statistics"""
        return self.middleware_stats.copy()
    
    def reset_stats(self):
        """Reset middleware statistics"""
        for key in self.middleware_stats:
            self.middleware_stats[key] = 0