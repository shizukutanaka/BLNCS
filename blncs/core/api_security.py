#!/usr/bin/env python3
"""
BLNCS API Security Middleware

Comprehensive API security with authentication, authorization, and protection.
"""

import asyncio
import json
import time
import re
from typing import Any, Dict, List, Optional, Callable, Union
from functools import wraps
from dataclasses import dataclass, field
from collections import defaultdict

import jwt
from ..core.exceptions import SecurityError, RateLimitError, ValidationError
from ..core.rate_limiter_enhanced import get_rate_limiter
from ..core.jwt_manager import JWTManager


@dataclass
class SecurityConfig:
    """Security configuration"""
    secret_key: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    rate_limits: Dict[str, int] = field(default_factory=dict)
    cors_origins: List[str] = field(default_factory=list)
    trusted_proxies: List[str] = field(default_factory=list)
    max_request_size: int = 10 * 1024 * 1024  # 10MB
    request_timeout: int = 30


@dataclass
class APISecurityContext:
    """API request security context"""
    user_id: Optional[str] = None
    roles: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    authenticated: bool = False
    rate_limited: bool = False


class APISecurityMiddleware:
    """Comprehensive API security middleware"""

    def __init__(self, config: SecurityConfig):
        self.config = config
        self.jwt_manager = JWTManager(
            secret_key=config.secret_key,
            algorithm=config.algorithm,
            access_token_expire_minutes=config.access_token_expire_minutes
        )
        self.rate_limiter = get_rate_limiter()

        # Security metrics
        self.metrics = {
            'total_requests': 0,
            'blocked_requests': 0,
            'rate_limited_requests': 0,
            'unauthorized_requests': 0,
            'malicious_requests': 0,
            'start_time': time.time()
        }

        # Compile regex patterns for validation
        self._sql_injection_patterns = [
            re.compile(r'(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b)', re.IGNORECASE),
            re.compile(r'(\bor\b|\band\b).*[\'"](.*)[\'"]', re.IGNORECASE),
            re.compile(r'(--|#|/\*)', re.IGNORECASE)
        ]

        self._xss_patterns = [
            re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
            re.compile(r'javascript:', re.IGNORECASE),
            re.compile(r'on\w+\s*=', re.IGNORECASE)
        ]

    async def __call__(self, request, call_next):
        """Main middleware function"""
        start_time = time.time()
        self.metrics['total_requests'] += 1

        try:
            # Create security context
            security_context = await self._build_security_context(request)

            # Pre-flight checks
            security_check = await self._pre_flight_security_check(request, security_context)
            if not security_check['allowed']:
                self.metrics['blocked_requests'] += 1
                return await self._create_security_response(security_check['reason'], security_check['status_code'])

            # Authenticate request
            auth_result = await self._authenticate_request(request, security_context)
            if not auth_result['success']:
                self.metrics['unauthorized_requests'] += 1
                return await self._create_security_response(auth_result['reason'], 401)

            # Rate limiting check
            rate_limit_result = await self._check_rate_limit(request, security_context)
            if not rate_limit_result['allowed']:
                self.metrics['rate_limited_requests'] += 1
                return await self._create_security_response("Rate limit exceeded", 429, {
                    'Retry-After': str(rate_limit_result['retry_after'])
                })

            # Input validation
            validation_result = self._validate_request_input(request)
            if not validation_result['valid']:
                return await self._create_security_response(f"Invalid input: {validation_result['reason']}", 400)

            # Execute request with security context
            response = await call_next(request)

            # Add security headers to response
            response = await self._add_security_headers(response)

            # Log security event
            await self._log_security_event(request, security_context, "success", time.time() - start_time)

            return response

        except Exception as e:
            self.metrics['malicious_requests'] += 1
            logger.error(f"Security middleware error: {e}")
            return await self._create_security_response("Internal server error", 500)

    async def _build_security_context(self, request) -> APISecurityContext:
        """Build security context from request"""
        context = APISecurityContext()

        # Extract client IP
        context.client_ip = self._get_client_ip(request)

        # Extract user agent
        context.user_agent = request.headers.get('user-agent', '')

        # Generate request ID
        context.request_id = request.headers.get('x-request-id', f"req_{int(time.time()*1000)}")

        return context

    async def _pre_flight_security_check(self, request, context: APISecurityContext) -> Dict[str, Any]:
        """Perform pre-flight security checks"""
        # Check request size
        if hasattr(request, 'content_length') and request.content_length:
            if request.content_length > self.config.max_request_size:
                return {
                    'allowed': False,
                    'reason': 'Request too large',
                    'status_code': 413
                }

        # Check for suspicious patterns in URL
        url = str(request.url) if hasattr(request, 'url') else str(request.path)
        if self._detect_suspicious_patterns(url):
            return {
                'allowed': False,
                'reason': 'Suspicious request pattern',
                'status_code': 400
            }

        # Check CORS
        if self.config.cors_origins:
            origin = request.headers.get('origin')
            if origin and origin not in self.config.cors_origins:
                return {
                    'allowed': False,
                    'reason': 'CORS policy violation',
                    'status_code': 403
                }

        return {'allowed': True}

    async def _authenticate_request(self, request, context: APISecurityContext) -> Dict[str, Any]:
        """Authenticate API request"""
        # Skip authentication for public endpoints
        if self._is_public_endpoint(request):
            return {'success': True, 'context': context}

        # Check for API key authentication
        api_key = request.headers.get('x-api-key')
        if api_key:
            auth_result = await self._authenticate_api_key(api_key, context)
            if auth_result['success']:
                return {'success': True, 'context': context}

        # Check for JWT authentication
        auth_header = request.headers.get('authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            auth_result = await self._authenticate_jwt(token, context)
            if auth_result['success']:
                return {'success': True, 'context': context}

        return {
            'success': False,
            'reason': 'Authentication required'
        }

    async def _authenticate_api_key(self, api_key: str, context: APISecurityContext) -> Dict[str, Any]:
        """Authenticate using API key"""
        # In a real implementation, this would check against a database
        # For now, we'll do a simple validation
        if len(api_key) < 16:
            return {'success': False, 'reason': 'Invalid API key format'}

        # Mock API key validation - in production this would check database
        if api_key.startswith('blncs_'):
            context.authenticated = True
            context.user_id = f"apikey_{api_key[:8]}"
            context.roles = ['api_user']
            context.permissions = ['read', 'write']

        return {'success': context.authenticated}

    async def _authenticate_jwt(self, token: str, context: APISecurityContext) -> Dict[str, Any]:
        """Authenticate using JWT"""
        try:
            payload = self.jwt_manager.decode_token(token)

            context.authenticated = True
            context.user_id = payload.get('user_id')
            context.roles = payload.get('roles', [])
            context.permissions = payload.get('permissions', [])

            return {'success': True}

        except jwt.ExpiredSignatureError:
            return {'success': False, 'reason': 'Token expired'}
        except jwt.InvalidTokenError:
            return {'success': False, 'reason': 'Invalid token'}
        except Exception as e:
            return {'success': False, 'reason': f'Token validation failed: {e}'}

    def _is_public_endpoint(self, request) -> bool:
        """Check if endpoint is public (no auth required)"""
        public_endpoints = ['/health', '/metrics', '/docs', '/openapi.json']

        path = request.path if hasattr(request, 'path') else str(request.url).split('?')[0]
        return any(path.startswith(endpoint) for endpoint in public_endpoints)

    async def _check_rate_limit(self, request, context: APISecurityContext) -> Dict[str, Any]:
        """Check rate limiting"""
        client_id = context.client_ip or 'unknown'
        endpoint = request.path if hasattr(request, 'path') else str(request.url).split('?')[0]

        # Use user ID if authenticated, otherwise use client IP
        identifier = context.user_id or client_id

        allowed, retry_after = self.rate_limiter.is_allowed(
            identifier,
            endpoint,
            rate_limit_rule=None  # Use default rules
        )

        return {
            'allowed': allowed,
            'retry_after': retry_after or 60
        }

    def _validate_request_input(self, request) -> Dict[str, Any]:
        """Validate request input for security issues"""
        # Check URL parameters
        if hasattr(request, 'query_params'):
            for key, value in request.query_params.items():
                if self._detect_suspicious_patterns(str(value)):
                    return {
                        'valid': False,
                        'reason': f'Suspicious parameter: {key}'
                    }

        # Check request body if present
        if hasattr(request, 'body') and request.body:
            try:
                body_str = request.body.decode('utf-8') if isinstance(request.body, bytes) else str(request.body)
                if self._detect_suspicious_patterns(body_str):
                    return {
                        'valid': False,
                        'reason': 'Suspicious content in request body'
                    }
            except Exception:
                pass  # Skip validation if body can't be decoded

        return {'valid': True}

    def _detect_suspicious_patterns(self, text: str) -> bool:
        """Detect suspicious patterns that might indicate attacks"""
        if not text:
            return False

        # Check for SQL injection patterns
        for pattern in self._sql_injection_patterns:
            if pattern.search(text):
                return True

        # Check for XSS patterns
        for pattern in self._xss_patterns:
            if pattern.search(text):
                return True

        # Check for path traversal
        if '../' in text or '..\\' in text:
            return True

        # Check for command injection
        dangerous_chars = [';', '|', '&', '`', '$']
        if any(char in text for char in dangerous_chars):
            return True

        return False

    async def _create_security_response(self, message: str, status_code: int, headers: Optional[Dict] = None) -> Any:
        """Create security error response"""
        response_data = {
            'error': 'Security violation',
            'message': message,
            'timestamp': time.time(),
            'request_id': getattr(self, '_current_request_id', 'unknown')
        }

        return {
            'status_code': status_code,
            'headers': {
                'Content-Type': 'application/json',
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'X-XSS-Protection': '1; mode=block',
                **(headers or {})
            },
            'body': json.dumps(response_data)
        }

    async def _add_security_headers(self, response) -> Any:
        """Add security headers to response"""
        if not hasattr(response, 'headers'):
            response.headers = {}

        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Content-Security-Policy': "default-src 'self'",
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
        }

        for header, value in security_headers.items():
            if header not in response.headers:
                response.headers[header] = value

        return response

    async def _log_security_event(self, request, context: APISecurityContext, result: str, duration: float):
        """Log security events for monitoring"""
        log_data = {
            'timestamp': time.time(),
            'client_ip': context.client_ip,
            'user_id': context.user_id,
            'method': getattr(request, 'method', 'UNKNOWN'),
            'path': getattr(request, 'path', str(getattr(request, 'url', ''))),
            'user_agent': context.user_agent,
            'result': result,
            'duration': duration,
            'authenticated': context.authenticated
        }

        # In production, this would be sent to a logging system
        logger.info(f"Security event: {json.dumps(log_data)}")

    def get_security_metrics(self) -> Dict[str, Any]:
        """Get security metrics"""
        uptime = time.time() - self.metrics['start_time']

        return {
            'uptime_seconds': uptime,
            'total_requests': self.metrics['total_requests'],
            'blocked_requests': self.metrics['blocked_requests'],
            'rate_limited_requests': self.metrics['rate_limited_requests'],
            'unauthorized_requests': self.metrics['unauthorized_requests'],
            'malicious_requests': self.metrics['malicious_requests'],
            'requests_per_second': self.metrics['total_requests'] / max(uptime, 1),
            'block_rate_percent': (self.metrics['blocked_requests'] / max(self.metrics['total_requests'], 1)) * 100
        }

    def _get_client_ip(self, request) -> Optional[str]:
        """Extract real client IP considering proxies"""
        # Check common proxy headers
        headers_to_check = [
            'x-forwarded-for',
            'x-real-ip',
            'cf-connecting-ip',
            'x-cluster-client-ip',
            'x-forwarded',
            'forwarded-for',
            'forwarded'
        ]

        for header in headers_to_check:
            value = request.headers.get(header)
            if value:
                # X-Forwarded-For can contain multiple IPs, take the first one
                ip = value.split(',')[0].strip()
                if self._is_valid_ip(ip):
                    return ip

        # Check direct connection
        if hasattr(request, 'client') and request.client:
            return request.client.host
        elif hasattr(request, 'remote'):
            return request.remote

        return None

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False


class AuthorizationMiddleware:
    """Authorization middleware for role-based access control"""

    def __init__(self):
        self.role_permissions = {
            'admin': ['read', 'write', 'admin', 'system'],
            'operator': ['read', 'write', 'system'],
            'user': ['read'],
            'readonly': ['read']
        }

    async def check_permission(self, context: APISecurityContext, required_permission: str, resource: str = None) -> bool:
        """Check if user has required permission"""
        if not context.authenticated:
            return False

        # Super admin check
        if 'admin' in context.roles:
            return True

        # Check specific permissions
        user_permissions = set(context.permissions)

        # Role-based permissions
        for role in context.roles:
            if role in self.role_permissions:
                user_permissions.update(self.role_permissions[role])

        return required_permission in user_permissions

    async def require_permission(self, permission: str, resource: str = None):
        """Decorator to require specific permission"""
        def decorator(func: Callable):
            @wraps(func)
            async def wrapper(request, *args, **kwargs):
                # Get security context from request
                context = getattr(request, 'security_context', None)
                if not context:
                    raise SecurityError("Security context not found")

                if not await self.check_permission(context, permission, resource):
                    raise SecurityError(f"Permission denied: {permission}")

                return await func(request, *args, **kwargs)
            return wrapper
        return decorator


# Global security middleware
_security_middleware = None

def get_security_middleware(config: Optional[SecurityConfig] = None) -> APISecurityMiddleware:
    """Get global security middleware instance"""
    global _security_middleware
    if _security_middleware is None:
        if not config:
            # Create default config - in production this would be loaded from environment
            config = SecurityConfig(
                secret_key="your-secret-key-change-in-production",
                cors_origins=["*"],
                rate_limits={
                    '/api/*': 100,
                    '/health': 30
                }
            )
        _security_middleware = APISecurityMiddleware(config)
    return _security_middleware
