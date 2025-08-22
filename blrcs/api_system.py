"""
Comprehensive API System
Enterprise-grade API infrastructure for national-level deployment
"""

import time
import json
import hashlib
import hmac
import jwt
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
import threading
import re


class APIVersion(Enum):
    """API version management"""
    V1 = "v1"
    V2 = "v2"
    V3 = "v3"
    LATEST = "v3"


class RateLimitStrategy(Enum):
    """Rate limiting strategies"""
    FIXED_WINDOW = "fixed_window"
    SLIDING_WINDOW = "sliding_window"
    TOKEN_BUCKET = "token_bucket"
    LEAKY_BUCKET = "leaky_bucket"


@dataclass
class APIEndpoint:
    """API endpoint definition"""
    path: str
    method: str
    handler: Callable
    version: APIVersion
    auth_required: bool = True
    rate_limit: int = 100
    timeout: int = 30
    description: str = ""
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    responses: Dict[int, str] = field(default_factory=dict)
    deprecated: bool = False
    deprecation_date: Optional[str] = None


@dataclass
class APIRequest:
    """API request context"""
    id: str
    method: str
    path: str
    headers: Dict[str, str]
    params: Dict[str, Any]
    body: Any
    client_ip: str
    timestamp: float = field(default_factory=time.time)
    user_id: Optional[str] = None
    session_id: Optional[str] = None


@dataclass
class APIResponse:
    """API response structure"""
    status_code: int
    body: Any
    headers: Dict[str, str] = field(default_factory=dict)
    processing_time: float = 0


class RateLimiter:
    """Advanced rate limiting implementation"""
    
    def __init__(self, strategy: RateLimitStrategy = RateLimitStrategy.SLIDING_WINDOW):
        self.strategy = strategy
        self.limits = {}
        self.windows = {}
        self.tokens = {}
        self.lock = threading.Lock()
        
    def check_limit(self, client_id: str, limit: int = 100, 
                   window: int = 60) -> Tuple[bool, Dict[str, Any]]:
        """Check if request is within rate limit"""
        with self.lock:
            if self.strategy == RateLimitStrategy.SLIDING_WINDOW:
                return self._sliding_window_check(client_id, limit, window)
            elif self.strategy == RateLimitStrategy.TOKEN_BUCKET:
                return self._token_bucket_check(client_id, limit, window)
            else:
                return self._fixed_window_check(client_id, limit, window)
                
    def _sliding_window_check(self, client_id: str, limit: int, 
                             window: int) -> Tuple[bool, Dict[str, Any]]:
        """Sliding window rate limit check"""
        now = time.time()
        window_start = now - window
        
        if client_id not in self.windows:
            self.windows[client_id] = []
            
        # Remove old entries
        self.windows[client_id] = [
            t for t in self.windows[client_id] if t > window_start
        ]
        
        current_count = len(self.windows[client_id])
        
        if current_count < limit:
            self.windows[client_id].append(now)
            remaining = limit - current_count - 1
            return True, {
                "limit": limit,
                "remaining": remaining,
                "reset": int(window_start + window)
            }
        else:
            remaining = 0
            reset_time = min(self.windows[client_id]) + window
            return False, {
                "limit": limit,
                "remaining": remaining,
                "reset": int(reset_time),
                "retry_after": int(reset_time - now)
            }
            
    def _token_bucket_check(self, client_id: str, limit: int, 
                           window: int) -> Tuple[bool, Dict[str, Any]]:
        """Token bucket rate limit check"""
        now = time.time()
        
        if client_id not in self.tokens:
            self.tokens[client_id] = {
                "tokens": limit,
                "last_refill": now
            }
            
        bucket = self.tokens[client_id]
        time_passed = now - bucket["last_refill"]
        
        # Refill tokens
        tokens_to_add = (time_passed / window) * limit
        bucket["tokens"] = min(limit, bucket["tokens"] + tokens_to_add)
        bucket["last_refill"] = now
        
        if bucket["tokens"] >= 1:
            bucket["tokens"] -= 1
            return True, {
                "limit": limit,
                "remaining": int(bucket["tokens"]),
                "reset": int(now + window)
            }
        else:
            time_to_next_token = (1 - bucket["tokens"]) * (window / limit)
            return False, {
                "limit": limit,
                "remaining": 0,
                "reset": int(now + time_to_next_token),
                "retry_after": int(time_to_next_token)
            }
            
    def _fixed_window_check(self, client_id: str, limit: int, 
                           window: int) -> Tuple[bool, Dict[str, Any]]:
        """Fixed window rate limit check"""
        now = time.time()
        window_key = int(now / window)
        
        if client_id not in self.limits:
            self.limits[client_id] = {}
            
        if window_key not in self.limits[client_id]:
            self.limits[client_id] = {window_key: 0}
            
        current_count = self.limits[client_id].get(window_key, 0)
        
        if current_count < limit:
            self.limits[client_id][window_key] = current_count + 1
            remaining = limit - current_count - 1
            reset_time = (window_key + 1) * window
            return True, {
                "limit": limit,
                "remaining": remaining,
                "reset": int(reset_time)
            }
        else:
            reset_time = (window_key + 1) * window
            return False, {
                "limit": limit,
                "remaining": 0,
                "reset": int(reset_time),
                "retry_after": int(reset_time - now)
            }


class APIAuthenticator:
    """API authentication handler"""
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self.sessions = {}
        self.api_keys = {}
        self.lock = threading.Lock()
        
    def generate_api_key(self, user_id: str, name: str = "default") -> str:
        """Generate API key for user"""
        key_data = f"{user_id}:{name}:{time.time()}"
        api_key = hashlib.sha256(key_data.encode()).hexdigest()
        
        with self.lock:
            self.api_keys[api_key] = {
                "user_id": user_id,
                "name": name,
                "created": time.time(),
                "last_used": None,
                "active": True
            }
            
        return api_key
        
    def validate_api_key(self, api_key: str) -> Optional[str]:
        """Validate API key and return user ID"""
        with self.lock:
            if api_key in self.api_keys:
                key_info = self.api_keys[api_key]
                if key_info["active"]:
                    key_info["last_used"] = time.time()
                    return key_info["user_id"]
        return None
        
    def generate_jwt_token(self, user_id: str, expires_in: int = 3600) -> str:
        """Generate JWT token"""
        payload = {
            "user_id": user_id,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(seconds=expires_in),
            "jti": str(uuid.uuid4())
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm="HS256")
        return token
        
    def validate_jwt_token(self, token: str) -> Optional[str]:
        """Validate JWT token and return user ID"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            return payload.get("user_id")
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
            
    def create_session(self, user_id: str) -> str:
        """Create session for user"""
        session_id = str(uuid.uuid4())
        
        with self.lock:
            self.sessions[session_id] = {
                "user_id": user_id,
                "created": time.time(),
                "last_activity": time.time(),
                "active": True
            }
            
        return session_id
        
    def validate_session(self, session_id: str) -> Optional[str]:
        """Validate session and return user ID"""
        with self.lock:
            if session_id in self.sessions:
                session = self.sessions[session_id]
                if session["active"]:
                    # Check session timeout (24 hours)
                    if time.time() - session["last_activity"] < 86400:
                        session["last_activity"] = time.time()
                        return session["user_id"]
                    else:
                        session["active"] = False
        return None


class APIValidator:
    """Request/Response validation"""
    
    def __init__(self):
        self.validators = {}
        
    def validate_request(self, request: APIRequest, 
                        schema: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate request against schema"""
        errors = []
        
        # Validate method
        if "method" in schema:
            if request.method not in schema["method"]:
                errors.append(f"Invalid method: {request.method}")
                
        # Validate headers
        if "required_headers" in schema:
            for header in schema["required_headers"]:
                if header not in request.headers:
                    errors.append(f"Missing required header: {header}")
                    
        # Validate parameters
        if "parameters" in schema:
            for param in schema["parameters"]:
                param_name = param["name"]
                param_type = param.get("type", "string")
                required = param.get("required", False)
                
                if required and param_name not in request.params:
                    errors.append(f"Missing required parameter: {param_name}")
                elif param_name in request.params:
                    if not self._validate_type(request.params[param_name], param_type):
                        errors.append(f"Invalid type for parameter {param_name}")
                        
        # Validate body
        if "body_schema" in schema and request.body:
            body_errors = self._validate_body(request.body, schema["body_schema"])
            errors.extend(body_errors)
            
        return len(errors) == 0, errors
        
    def _validate_type(self, value: Any, expected_type: str) -> bool:
        """Validate value type"""
        type_map = {
            "string": str,
            "integer": int,
            "float": float,
            "boolean": bool,
            "array": list,
            "object": dict
        }
        
        if expected_type in type_map:
            return isinstance(value, type_map[expected_type])
        return True
        
    def _validate_body(self, body: Any, schema: Dict[str, Any]) -> List[str]:
        """Validate request body"""
        errors = []
        
        if not isinstance(body, dict):
            return ["Body must be an object"]
            
        # Check required fields
        if "required" in schema:
            for field in schema["required"]:
                if field not in body:
                    errors.append(f"Missing required field: {field}")
                    
        # Check field types
        if "properties" in schema:
            for field, field_schema in schema["properties"].items():
                if field in body:
                    field_type = field_schema.get("type", "string")
                    if not self._validate_type(body[field], field_type):
                        errors.append(f"Invalid type for field {field}")
                        
        return errors


class APICache:
    """API response caching"""
    
    def __init__(self, max_size: int = 1000, ttl: int = 300):
        self.cache = {}
        self.access_times = {}
        self.max_size = max_size
        self.ttl = ttl
        self.lock = threading.Lock()
        
    def get(self, key: str) -> Optional[Any]:
        """Get cached response"""
        with self.lock:
            if key in self.cache:
                # Check TTL
                if time.time() - self.access_times[key] < self.ttl:
                    self.access_times[key] = time.time()
                    return self.cache[key]
                else:
                    # Expired
                    del self.cache[key]
                    del self.access_times[key]
        return None
        
    def set(self, key: str, value: Any):
        """Cache response"""
        with self.lock:
            # Evict old entries if needed
            if len(self.cache) >= self.max_size:
                # Remove least recently used
                lru_key = min(self.access_times, key=self.access_times.get)
                del self.cache[lru_key]
                del self.access_times[lru_key]
                
            self.cache[key] = value
            self.access_times[key] = time.time()
            
    def clear(self):
        """Clear cache"""
        with self.lock:
            self.cache.clear()
            self.access_times.clear()


class APIRouter:
    """API routing system"""
    
    def __init__(self):
        self.routes = {}
        self.middleware = []
        
    def register(self, endpoint: APIEndpoint):
        """Register API endpoint"""
        key = f"{endpoint.method}:{endpoint.version.value}:{endpoint.path}"
        self.routes[key] = endpoint
        
    def add_middleware(self, middleware: Callable):
        """Add middleware function"""
        self.middleware.append(middleware)
        
    def route(self, request: APIRequest) -> Optional[APIEndpoint]:
        """Find matching endpoint for request"""
        # Extract version from path
        path_parts = request.path.split("/")
        version = APIVersion.LATEST
        
        if len(path_parts) > 1 and path_parts[1] in [v.value for v in APIVersion]:
            version = APIVersion(path_parts[1])
            path = "/" + "/".join(path_parts[2:])
        else:
            path = request.path
            
        # Try exact match
        key = f"{request.method}:{version.value}:{path}"
        if key in self.routes:
            return self.routes[key]
            
        # Try pattern matching
        for route_key, endpoint in self.routes.items():
            method, ver, pattern = route_key.split(":", 2)
            if method == request.method and ver == version.value:
                if self._match_pattern(path, pattern):
                    return endpoint
                    
        return None
        
    def _match_pattern(self, path: str, pattern: str) -> bool:
        """Match path against pattern with parameters"""
        # Convert pattern to regex
        # /users/{id} -> /users/([^/]+)
        regex_pattern = pattern
        regex_pattern = regex_pattern.replace("{", "(?P<")
        regex_pattern = regex_pattern.replace("}", ">[^/]+)")
        regex_pattern = f"^{regex_pattern}$"
        
        return re.match(regex_pattern, path) is not None


class APIServer:
    """Main API server"""
    
    def __init__(self, secret_key: str = None):
        self.secret_key = secret_key or self._generate_secret_key()
        self.router = APIRouter()
        self.rate_limiter = RateLimiter()
        self.authenticator = APIAuthenticator(self.secret_key)
        self.validator = APIValidator()
        self.cache = APICache()
        self.request_counter = 0
        self.error_counter = 0
        self.start_time = time.time()
        
    def _generate_secret_key(self) -> str:
        """Generate secure secret key"""
        return hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()
        
    def register_endpoint(self, path: str, method: str = "GET", 
                         version: APIVersion = APIVersion.LATEST,
                         auth_required: bool = True,
                         rate_limit: int = 100):
        """Decorator to register API endpoint"""
        def decorator(func):
            endpoint = APIEndpoint(
                path=path,
                method=method,
                handler=func,
                version=version,
                auth_required=auth_required,
                rate_limit=rate_limit,
                description=func.__doc__ or ""
            )
            self.router.register(endpoint)
            
            @wraps(func)
            def wrapper(*args, **kwargs):
                return func(*args, **kwargs)
            return wrapper
        return decorator
        
    def process_request(self, request: APIRequest) -> APIResponse:
        """Process API request"""
        start_time = time.time()
        self.request_counter += 1
        
        try:
            # Find endpoint
            endpoint = self.router.route(request)
            if not endpoint:
                return APIResponse(
                    status_code=404,
                    body={"error": "Endpoint not found"}
                )
                
            # Check if deprecated
            if endpoint.deprecated:
                headers = {"X-Deprecated": "true"}
                if endpoint.deprecation_date:
                    headers["X-Deprecation-Date"] = endpoint.deprecation_date
            else:
                headers = {}
                
            # Authentication
            if endpoint.auth_required:
                user_id = self._authenticate(request)
                if not user_id:
                    return APIResponse(
                        status_code=401,
                        body={"error": "Authentication required"}
                    )
                request.user_id = user_id
                
            # Rate limiting
            client_id = request.user_id or request.client_ip
            allowed, limit_info = self.rate_limiter.check_limit(
                client_id, endpoint.rate_limit
            )
            
            headers.update({
                "X-RateLimit-Limit": str(limit_info["limit"]),
                "X-RateLimit-Remaining": str(limit_info["remaining"]),
                "X-RateLimit-Reset": str(limit_info["reset"])
            })
            
            if not allowed:
                headers["Retry-After"] = str(limit_info.get("retry_after", 60))
                return APIResponse(
                    status_code=429,
                    body={"error": "Rate limit exceeded"},
                    headers=headers
                )
                
            # Check cache
            cache_key = self._get_cache_key(request)
            cached_response = self.cache.get(cache_key)
            if cached_response:
                headers["X-Cache"] = "HIT"
                cached_response.headers = headers
                return cached_response
                
            # Execute handler
            try:
                result = endpoint.handler(request)
                response = APIResponse(
                    status_code=200,
                    body=result,
                    headers=headers
                )
                
                # Cache successful responses
                if response.status_code == 200:
                    self.cache.set(cache_key, response)
                    
            except Exception as e:
                self.error_counter += 1
                response = APIResponse(
                    status_code=500,
                    body={"error": "Internal server error"},
                    headers=headers
                )
                
        except Exception as e:
            self.error_counter += 1
            response = APIResponse(
                status_code=500,
                body={"error": "Internal server error"}
            )
            
        response.processing_time = time.time() - start_time
        response.headers["X-Response-Time"] = f"{response.processing_time:.3f}s"
        
        return response
        
    def _authenticate(self, request: APIRequest) -> Optional[str]:
        """Authenticate request"""
        # Check API key
        if "X-API-Key" in request.headers:
            return self.authenticator.validate_api_key(request.headers["X-API-Key"])
            
        # Check JWT token
        if "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]
                return self.authenticator.validate_jwt_token(token)
                
        # Check session
        if "X-Session-ID" in request.headers:
            return self.authenticator.validate_session(request.headers["X-Session-ID"])
            
        return None
        
    def _get_cache_key(self, request: APIRequest) -> str:
        """Generate cache key for request"""
        key_parts = [
            request.method,
            request.path,
            json.dumps(request.params, sort_keys=True),
            request.user_id or ""
        ]
        return hashlib.md5(":".join(key_parts).encode()).hexdigest()
        
    def get_stats(self) -> Dict[str, Any]:
        """Get API statistics"""
        uptime = time.time() - self.start_time
        
        return {
            "uptime_seconds": uptime,
            "total_requests": self.request_counter,
            "total_errors": self.error_counter,
            "error_rate": (self.error_counter / self.request_counter * 100) 
                         if self.request_counter > 0 else 0,
            "requests_per_second": self.request_counter / uptime if uptime > 0 else 0,
            "cache_size": len(self.cache.cache),
            "active_sessions": len(self.authenticator.sessions),
            "registered_endpoints": len(self.router.routes)
        }


# Global API server instance
api_server = APIServer()


def get_api_server() -> APIServer:
    """Get the global API server instance"""
    return api_server