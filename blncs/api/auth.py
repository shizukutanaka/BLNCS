#!/usr/bin/env python3
"""
BLNCS API Authentication
Comprehensive authentication and authorization system for API endpoints.
"""

import hashlib
import secrets
import time
from functools import wraps
from flask import request, jsonify, g
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Callable
import logging

logger = logging.getLogger(__name__)

class APIKeyManager:
    """API key management system"""
    
    def __init__(self):
        self.api_keys: Dict[str, Dict[str, Any]] = {}
        self.key_usage: Dict[str, Dict[str, Any]] = {}
    
    def generate_api_key(self, name: str, permissions: list = None) -> str:
        """Generate a new API key"""
        api_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        self.api_keys[key_hash] = {
            'name': name,
            'permissions': permissions or ['read', 'write'],
            'created_at': datetime.now().isoformat(),
            'last_used': None,
            'usage_count': 0,
            'active': True
        }
        
        return api_key
    
    def validate_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Validate API key and return key info"""
        if not api_key:
            return None
            
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        key_info = self.api_keys.get(key_hash)
        
        if key_info and key_info.get('active', False):
            # Update usage
            key_info['last_used'] = datetime.now().isoformat()
            key_info['usage_count'] += 1
            
            # Track usage statistics
            self.key_usage[key_hash] = self.key_usage.get(key_hash, {})
            today = datetime.now().date().isoformat()
            self.key_usage[key_hash][today] = self.key_usage[key_hash].get(today, 0) + 1
            
            return key_info
        
        return None
    
    def revoke_api_key(self, api_key: str) -> bool:
        """Revoke an API key"""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        if key_hash in self.api_keys:
            self.api_keys[key_hash]['active'] = False
            return True
        return False

class RateLimiter:
    """Rate limiting system"""
    
    def __init__(self, default_limit: int = 100, window_seconds: int = 60):
        self.default_limit = default_limit
        self.window_seconds = window_seconds
        self.requests: Dict[str, list] = {}
    
    def is_allowed(self, identifier: str, limit: Optional[int] = None) -> tuple[bool, Dict[str, Any]]:
        """Check if request is allowed under rate limit"""
        limit = limit or self.default_limit
        now = time.time()
        window_start = now - self.window_seconds
        
        # Clean old requests
        if identifier in self.requests:
            self.requests[identifier] = [
                req_time for req_time in self.requests[identifier]
                if req_time > window_start
            ]
        else:
            self.requests[identifier] = []
        
        # Check limit
        current_count = len(self.requests[identifier])
        allowed = current_count < limit
        
        if allowed:
            self.requests[identifier].append(now)
        
        return allowed, {
            'limit': limit,
            'remaining': max(0, limit - current_count - (1 if allowed else 0)),
            'reset_time': int(window_start + self.window_seconds),
            'window_seconds': self.window_seconds
        }

class AuthManager:
    """Comprehensive authentication manager"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.api_key_manager = APIKeyManager()
        self.rate_limiter = RateLimiter(
            default_limit=self.config.get('rate_limit', {}).get('requests_per_minute', 100),
            window_seconds=60
        )
        
        # Initialize with default API key if configured
        default_key = self.config.get('default_api_key')
        if default_key:
            key_hash = hashlib.sha256(default_key.encode()).hexdigest()
            self.api_key_manager.api_keys[key_hash] = {
                'name': 'default',
                'permissions': ['read', 'write', 'admin'],
                'created_at': datetime.now().isoformat(),
                'last_used': None,
                'usage_count': 0,
                'active': True
            }
    
    def authenticate_request(self, request) -> Optional[Dict[str, Any]]:
        """Authenticate incoming request"""
        # Check API key
        api_key = None
        
        # Try Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            api_key = auth_header[7:]
        
        # Try X-API-Key header
        if not api_key:
            api_key = request.headers.get('X-API-Key')
        
        # Try query parameter
        if not api_key:
            api_key = request.args.get('api_key')
        
        if not api_key:
            return None
        
        return self.api_key_manager.validate_api_key(api_key)
    
    def check_rate_limit(self, request, key_info: Dict[str, Any] = None) -> tuple[bool, Dict[str, Any]]:
        """Check rate limiting"""
        # Use API key name or IP address as identifier
        if key_info:
            identifier = f"key:{key_info['name']}"
        else:
            identifier = f"ip:{request.remote_addr}"
        
        return self.rate_limiter.is_allowed(identifier)
    
    def has_permission(self, key_info: Dict[str, Any], required_permission: str) -> bool:
        """Check if key has required permission"""
        if not key_info:
            return False
        
        permissions = key_info.get('permissions', [])
        return 'admin' in permissions or required_permission in permissions
    
    def generate_key(self, name: str, permissions: list = None) -> str:
        """Generate new API key"""
        return self.api_key_manager.generate_api_key(name, permissions)
    
    def revoke_key(self, api_key: str) -> bool:
        """Revoke API key"""
        return self.api_key_manager.revoke_api_key(api_key)
    
    def get_usage_stats(self) -> Dict[str, Any]:
        """Get authentication usage statistics"""
        return {
            'total_keys': len(self.api_key_manager.api_keys),
            'active_keys': len([k for k in self.api_key_manager.api_keys.values() if k.get('active')]),
            'usage_today': sum(
                usage.get(datetime.now().date().isoformat(), 0)
                for usage in self.api_key_manager.key_usage.values()
            )
        }

# Decorators
def api_key_required(f: Callable) -> Callable:
    """Decorator requiring valid API key"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import current_app
        
        auth_manager = getattr(current_app, 'auth_manager', None)
        if not auth_manager:
            return jsonify({'error': 'Authentication not configured'}), 500
        
        # Authenticate request
        key_info = auth_manager.authenticate_request(request)
        if not key_info:
            return jsonify({'error': 'Invalid or missing API key'}), 401
        
        # Store key info for use in endpoint
        g.api_key_info = key_info
        
        return f(*args, **kwargs)
    
    return decorated_function

def require_permission(permission: str):
    """Decorator requiring specific permission"""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import current_app
            
            auth_manager = getattr(current_app, 'auth_manager', None)
            if not auth_manager:
                return jsonify({'error': 'Authentication not configured'}), 500
            
            key_info = getattr(g, 'api_key_info', None)
            if not key_info:
                return jsonify({'error': 'Authentication required'}), 401
            
            if not auth_manager.has_permission(key_info, permission):
                return jsonify({'error': f'Permission "{permission}" required'}), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

def rate_limit(limit: int = None):
    """Decorator for rate limiting"""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import current_app
            
            auth_manager = getattr(current_app, 'auth_manager', None)
            if not auth_manager:
                return f(*args, **kwargs)  # Skip rate limiting if not configured
            
            key_info = getattr(g, 'api_key_info', None)
            allowed, rate_info = auth_manager.check_rate_limit(request, key_info)
            
            if not allowed:
                response = jsonify({
                    'error': 'Rate limit exceeded',
                    'limit': rate_info['limit'],
                    'reset_time': rate_info['reset_time']
                })
                response.status_code = 429
                response.headers['X-RateLimit-Limit'] = str(rate_info['limit'])
                response.headers['X-RateLimit-Remaining'] = str(rate_info['remaining'])
                response.headers['X-RateLimit-Reset'] = str(rate_info['reset_time'])
                return response
            
            # Add rate limit headers to successful response
            response = f(*args, **kwargs)
            if hasattr(response, 'headers'):
                response.headers['X-RateLimit-Limit'] = str(rate_info['limit'])
                response.headers['X-RateLimit-Remaining'] = str(rate_info['remaining'])
                response.headers['X-RateLimit-Reset'] = str(rate_info['reset_time'])
            
            return response
        
        return decorated_function
    return decorator

def admin_required(f: Callable) -> Callable:
    """Decorator requiring admin permission"""
    return require_permission('admin')(f)

def read_only(f: Callable) -> Callable:
    """Decorator requiring only read permission"""
    return require_permission('read')(f)