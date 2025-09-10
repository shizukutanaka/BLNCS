"""
Enterprise API Gateway and Service Mesh
High-performance traffic management with advanced routing, load balancing, and resilience patterns.
"""

import asyncio
import json
import logging
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Callable, Tuple
from enum import Enum
from dataclasses import dataclass, field, asdict
import aiohttp
import aioredis
import consul
from circuit_breaker import CircuitBreaker as CB
import threading
from collections import defaultdict, deque
import statistics
import random
import uuid

logger = logging.getLogger(__name__)

class LoadBalancingStrategy(Enum):
    ROUND_ROBIN = "round_robin"
    WEIGHTED_ROUND_ROBIN = "weighted_round_robin"
    LEAST_CONNECTIONS = "least_connections"
    LEAST_RESPONSE_TIME = "least_response_time"
    IP_HASH = "ip_hash"
    CONSISTENT_HASH = "consistent_hash"
    RANDOM = "random"
    GEOLOCATION = "geolocation"

class CircuitBreakerState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

class AuthenticationType(Enum):
    JWT = "jwt"
    OAUTH2 = "oauth2"
    API_KEY = "api_key"
    BASIC_AUTH = "basic_auth"
    MUTUAL_TLS = "mutual_tls"

class ServiceDiscoveryProvider(Enum):
    CONSUL = "consul"
    ETCD = "etcd"
    KUBERNETES = "kubernetes"
    DNS = "dns"
    STATIC = "static"

@dataclass
class ServiceInstance:
    id: str
    address: str
    port: int
    weight: int = 100
    healthy: bool = True
    metadata: Dict[str, str] = field(default_factory=dict)
    last_health_check: datetime = field(default_factory=datetime.utcnow)
    response_times: deque = field(default_factory=lambda: deque(maxlen=100))
    connection_count: int = 0

@dataclass
class RouteConfig:
    path: str
    methods: List[str] = field(default_factory=lambda: ["GET"])
    service_name: str = ""
    upstream_path: str = ""
    timeout_ms: int = 30000
    retry_count: int = 3
    circuit_breaker_enabled: bool = True
    rate_limit_per_minute: int = 1000
    authentication_required: bool = True
    authentication_types: List[AuthenticationType] = field(default_factory=list)
    cors_enabled: bool = True
    cors_origins: List[str] = field(default_factory=lambda: ["*"])
    middleware: List[str] = field(default_factory=list)
    load_balancing_strategy: LoadBalancingStrategy = LoadBalancingStrategy.ROUND_ROBIN
    health_check_path: str = "/health"
    priority: int = 100

@dataclass
class GatewayConfig:
    host: str = "0.0.0.0"
    port: int = 8080
    service_discovery_provider: ServiceDiscoveryProvider = ServiceDiscoveryProvider.CONSUL
    consul_host: str = "localhost"
    consul_port: int = 8500
    redis_url: str = "redis://localhost:6379"
    default_timeout_ms: int = 30000
    default_retry_count: int = 3
    circuit_breaker_failure_threshold: int = 5
    circuit_breaker_timeout_ms: int = 60000
    rate_limit_window_ms: int = 60000
    health_check_interval_ms: int = 30000
    max_connections_per_service: int = 100
    enable_request_logging: bool = True
    enable_metrics: bool = True
    enable_tracing: bool = True
    ssl_enabled: bool = False
    ssl_cert_path: str = ""
    ssl_key_path: str = ""

class RateLimiter:
    def __init__(self, redis_client: aioredis.Redis, window_ms: int = 60000):
        self.redis = redis_client
        self.window_ms = window_ms
        self.local_cache = defaultdict(deque)
        self.cache_lock = threading.Lock()
    
    async def is_allowed(self, key: str, limit: int) -> bool:
        """Check if request is allowed based on rate limit"""
        now = int(time.time() * 1000)
        window_start = now - self.window_ms
        
        try:
            # Use Redis for distributed rate limiting
            async with self.redis.pipeline() as pipe:
                await pipe.zremrangebyscore(key, 0, window_start)
                await pipe.zcard(key)
                await pipe.zadd(key, {str(uuid.uuid4()): now})
                await pipe.expire(key, self.window_ms // 1000)
                results = await pipe.execute()
                
                current_count = results[1]
                return current_count < limit
                
        except Exception as e:
            logger.error(f"Redis rate limiter error: {e}")
            # Fallback to local rate limiting
            return self._local_rate_limit(key, limit, now, window_start)
    
    def _local_rate_limit(self, key: str, limit: int, now: int, window_start: int) -> bool:
        """Local fallback rate limiting"""
        with self.cache_lock:
            timestamps = self.local_cache[key]
            
            # Remove old timestamps
            while timestamps and timestamps[0] < window_start:
                timestamps.popleft()
            
            if len(timestamps) < limit:
                timestamps.append(now)
                return True
            
            return False

class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, timeout_ms: int = 60000):
        self.failure_threshold = failure_threshold
        self.timeout_ms = timeout_ms
        self.failure_count = 0
        self.last_failure_time = None
        self.state = CircuitBreakerState.CLOSED
        self.lock = threading.Lock()
    
    async def call(self, func: Callable, *args, **kwargs):
        """Execute function with circuit breaker protection"""
        with self.lock:
            if self.state == CircuitBreakerState.OPEN:
                if self._should_attempt_reset():
                    self.state = CircuitBreakerState.HALF_OPEN
                else:
                    raise Exception("Circuit breaker is OPEN")
        
        try:
            result = await func(*args, **kwargs)
            await self._on_success()
            return result
        except Exception as e:
            await self._on_failure()
            raise
    
    def _should_attempt_reset(self) -> bool:
        """Check if circuit breaker should attempt reset"""
        return (
            self.last_failure_time and 
            (time.time() * 1000 - self.last_failure_time) > self.timeout_ms
        )
    
    async def _on_success(self):
        """Handle successful call"""
        with self.lock:
            self.failure_count = 0
            self.state = CircuitBreakerState.CLOSED
    
    async def _on_failure(self):
        """Handle failed call"""
        with self.lock:
            self.failure_count += 1
            self.last_failure_time = time.time() * 1000
            
            if self.failure_count >= self.failure_threshold:
                self.state = CircuitBreakerState.OPEN

class LoadBalancer:
    def __init__(self, strategy: LoadBalancingStrategy = LoadBalancingStrategy.ROUND_ROBIN):
        self.strategy = strategy
        self.round_robin_counter = defaultdict(int)
        self.consistent_hash_ring = {}
    
    async def select_instance(self, instances: List[ServiceInstance], 
                            client_info: Optional[Dict[str, Any]] = None) -> Optional[ServiceInstance]:
        """Select service instance based on load balancing strategy"""
        healthy_instances = [i for i in instances if i.healthy]
        
        if not healthy_instances:
            return None
        
        if self.strategy == LoadBalancingStrategy.ROUND_ROBIN:
            return self._round_robin_select(healthy_instances)
        elif self.strategy == LoadBalancingStrategy.WEIGHTED_ROUND_ROBIN:
            return self._weighted_round_robin_select(healthy_instances)
        elif self.strategy == LoadBalancingStrategy.LEAST_CONNECTIONS:
            return self._least_connections_select(healthy_instances)
        elif self.strategy == LoadBalancingStrategy.LEAST_RESPONSE_TIME:
            return self._least_response_time_select(healthy_instances)
        elif self.strategy == LoadBalancingStrategy.IP_HASH:
            return self._ip_hash_select(healthy_instances, client_info)
        elif self.strategy == LoadBalancingStrategy.CONSISTENT_HASH:
            return self._consistent_hash_select(healthy_instances, client_info)
        elif self.strategy == LoadBalancingStrategy.RANDOM:
            return random.choice(healthy_instances)
        else:
            return healthy_instances[0]
    
    def _round_robin_select(self, instances: List[ServiceInstance]) -> ServiceInstance:
        """Round-robin selection"""
        service_key = id(instances)
        index = self.round_robin_counter[service_key] % len(instances)
        self.round_robin_counter[service_key] += 1
        return instances[index]
    
    def _weighted_round_robin_select(self, instances: List[ServiceInstance]) -> ServiceInstance:
        """Weighted round-robin selection"""
        total_weight = sum(i.weight for i in instances)
        if total_weight == 0:
            return instances[0]
        
        service_key = id(instances)
        counter = self.round_robin_counter[service_key]
        
        for instance in instances:
            counter -= instance.weight
            if counter <= 0:
                self.round_robin_counter[service_key] = total_weight + counter
                return instance
        
        return instances[0]
    
    def _least_connections_select(self, instances: List[ServiceInstance]) -> ServiceInstance:
        """Least connections selection"""
        return min(instances, key=lambda i: i.connection_count)
    
    def _least_response_time_select(self, instances: List[ServiceInstance]) -> ServiceInstance:
        """Least response time selection"""
        def avg_response_time(instance):
            if not instance.response_times:
                return 0
            return statistics.mean(instance.response_times)
        
        return min(instances, key=avg_response_time)
    
    def _ip_hash_select(self, instances: List[ServiceInstance], 
                       client_info: Optional[Dict[str, Any]]) -> ServiceInstance:
        """IP hash selection"""
        if not client_info or 'remote_addr' not in client_info:
            return instances[0]
        
        ip_hash = hashlib.md5(client_info['remote_addr'].encode()).hexdigest()
        index = int(ip_hash, 16) % len(instances)
        return instances[index]
    
    def _consistent_hash_select(self, instances: List[ServiceInstance], 
                               client_info: Optional[Dict[str, Any]]) -> ServiceInstance:
        """Consistent hash selection"""
        if not client_info:
            return instances[0]
        
        # Build hash ring if not exists
        ring_key = id(instances)
        if ring_key not in self.consistent_hash_ring:
            self._build_hash_ring(instances, ring_key)
        
        # Find instance
        client_hash = self._hash_client(client_info)
        return self._find_instance_in_ring(client_hash, ring_key)
    
    def _build_hash_ring(self, instances: List[ServiceInstance], ring_key):
        """Build consistent hash ring"""
        ring = {}
        for instance in instances:
            for i in range(instance.weight):
                node_hash = hashlib.md5(f"{instance.id}:{i}".encode()).hexdigest()
                ring[int(node_hash, 16)] = instance
        
        self.consistent_hash_ring[ring_key] = dict(sorted(ring.items()))
    
    def _hash_client(self, client_info: Dict[str, Any]) -> int:
        """Hash client information"""
        client_str = json.dumps(client_info, sort_keys=True)
        return int(hashlib.md5(client_str.encode()).hexdigest(), 16)
    
    def _find_instance_in_ring(self, client_hash: int, ring_key) -> ServiceInstance:
        """Find instance in consistent hash ring"""
        ring = self.consistent_hash_ring[ring_key]
        
        for node_hash in sorted(ring.keys()):
            if client_hash <= node_hash:
                return ring[node_hash]
        
        # Wrap around to first node
        return ring[min(ring.keys())]

class ServiceDiscovery:
    def __init__(self, config: GatewayConfig):
        self.config = config
        self.consul_client = None
        self.service_registry = defaultdict(list)
        self.health_check_task = None
    
    async def initialize(self):
        """Initialize service discovery"""
        if self.config.service_discovery_provider == ServiceDiscoveryProvider.CONSUL:
            await self._initialize_consul()
        
        # Start health checking
        self.health_check_task = asyncio.create_task(self._health_check_loop())
    
    async def _initialize_consul(self):
        """Initialize Consul client"""
        try:
            self.consul_client = consul.Consul(
                host=self.config.consul_host,
                port=self.config.consul_port
            )
            logger.info("Consul client initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Consul: {e}")
    
    async def discover_services(self, service_name: str) -> List[ServiceInstance]:
        """Discover service instances"""
        if self.config.service_discovery_provider == ServiceDiscoveryProvider.CONSUL:
            return await self._discover_consul_services(service_name)
        elif self.config.service_discovery_provider == ServiceDiscoveryProvider.STATIC:
            return self.service_registry.get(service_name, [])
        else:
            return []
    
    async def _discover_consul_services(self, service_name: str) -> List[ServiceInstance]:
        """Discover services from Consul"""
        if not self.consul_client:
            return []
        
        try:
            _, services = self.consul_client.health.service(service_name, passing=True)
            instances = []
            
            for service in services:
                instance = ServiceInstance(
                    id=service['Service']['ID'],
                    address=service['Service']['Address'],
                    port=service['Service']['Port'],
                    weight=service['Service'].get('Weights', {}).get('Passing', 100),
                    metadata=service['Service'].get('Meta', {})
                )
                instances.append(instance)
            
            return instances
            
        except Exception as e:
            logger.error(f"Error discovering Consul services: {e}")
            return []
    
    async def register_service(self, service_name: str, instance: ServiceInstance):
        """Register service instance"""
        if self.config.service_discovery_provider == ServiceDiscoveryProvider.STATIC:
            self.service_registry[service_name].append(instance)
    
    async def _health_check_loop(self):
        """Health check loop for service instances"""
        while True:
            try:
                for service_name, instances in self.service_registry.items():
                    for instance in instances:
                        await self._check_instance_health(instance)
                
                await asyncio.sleep(self.config.health_check_interval_ms / 1000)
                
            except Exception as e:
                logger.error(f"Health check error: {e}")
                await asyncio.sleep(5)
    
    async def _check_instance_health(self, instance: ServiceInstance):
        """Check health of service instance"""
        try:
            url = f"http://{instance.address}:{instance.port}/health"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    instance.healthy = response.status == 200
                    instance.last_health_check = datetime.utcnow()
                    
        except Exception:
            instance.healthy = False
            instance.last_health_check = datetime.utcnow()

class AuthenticationHandler:
    def __init__(self):
        self.jwt_secret = "your-jwt-secret"  # Should be configurable
        self.api_keys = set()  # Should be loaded from database
    
    async def authenticate(self, request_headers: Dict[str, str], 
                          auth_types: List[AuthenticationType]) -> bool:
        """Authenticate request"""
        for auth_type in auth_types:
            if auth_type == AuthenticationType.API_KEY:
                if await self._verify_api_key(request_headers):
                    return True
            elif auth_type == AuthenticationType.JWT:
                if await self._verify_jwt(request_headers):
                    return True
            # Add other authentication methods
        
        return False
    
    async def _verify_api_key(self, headers: Dict[str, str]) -> bool:
        """Verify API key authentication"""
        api_key = headers.get('X-API-Key', headers.get('Authorization', ''))
        return api_key in self.api_keys
    
    async def _verify_jwt(self, headers: Dict[str, str]) -> bool:
        """Verify JWT authentication"""
        auth_header = headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return False
        
        token = auth_header[7:]  # Remove 'Bearer ' prefix
        # Implement JWT verification logic
        return len(token) > 0  # Placeholder

class TrafficManager:
    def __init__(self, config: GatewayConfig):
        self.config = config
        self.request_stats = defaultdict(lambda: {'count': 0, 'errors': 0, 'total_time': 0})
        self.active_connections = defaultdict(int)
    
    async def handle_request(self, method: str, path: str, headers: Dict[str, str],
                           body: bytes, client_info: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
        """Handle incoming request"""
        start_time = time.time()
        
        try:
            # Find matching route
            route = self._find_route(method, path)
            if not route:
                return 404, {}, b'Route not found'
            
            # Check rate limiting
            if not await self._check_rate_limit(route, client_info):
                return 429, {}, b'Rate limit exceeded'
            
            # Authenticate request
            if route.authentication_required:
                if not await self._authenticate_request(headers, route.authentication_types):
                    return 401, {}, b'Authentication failed'
            
            # Forward request to upstream service
            response_status, response_headers, response_body = await self._forward_request(
                route, method, headers, body, client_info
            )
            
            # Record metrics
            self._record_request_metrics(route, start_time, response_status)
            
            return response_status, response_headers, response_body
            
        except Exception as e:
            logger.error(f"Error handling request: {e}")
            self._record_request_metrics(None, start_time, 500)
            return 500, {}, b'Internal server error'
    
    def _find_route(self, method: str, path: str) -> Optional[RouteConfig]:
        """Find matching route configuration"""
        # This should be implemented with proper route matching logic
        # For now, return a default route
        return RouteConfig(
            path=path,
            methods=[method],
            service_name="blncs-core"
        )
    
    async def _check_rate_limit(self, route: RouteConfig, client_info: Dict[str, Any]) -> bool:
        """Check rate limiting"""
        # Implement rate limiting logic
        return True  # Placeholder
    
    async def _authenticate_request(self, headers: Dict[str, str], 
                                   auth_types: List[AuthenticationType]) -> bool:
        """Authenticate request"""
        auth_handler = AuthenticationHandler()
        return await auth_handler.authenticate(headers, auth_types)
    
    async def _forward_request(self, route: RouteConfig, method: str, 
                              headers: Dict[str, str], body: bytes,
                              client_info: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
        """Forward request to upstream service"""
        # Implement request forwarding logic
        return 200, {}, b'{"status": "ok"}'  # Placeholder
    
    def _record_request_metrics(self, route: Optional[RouteConfig], 
                               start_time: float, status_code: int):
        """Record request metrics"""
        duration = time.time() - start_time
        route_key = route.path if route else "unknown"
        
        stats = self.request_stats[route_key]
        stats['count'] += 1
        stats['total_time'] += duration
        
        if status_code >= 400:
            stats['errors'] += 1

class APIGateway:
    def __init__(self, config: GatewayConfig):
        self.config = config
        self.service_discovery = ServiceDiscovery(config)
        self.load_balancer = LoadBalancer()
        self.rate_limiter = None
        self.circuit_breakers = {}
        self.traffic_manager = TrafficManager(config)
        self.redis_client = None
        self.server = None
        self.running = False
    
    async def initialize(self):
        """Initialize API gateway"""
        try:
            # Initialize Redis
            self.redis_client = aioredis.from_url(self.config.redis_url)
            
            # Initialize rate limiter
            self.rate_limiter = RateLimiter(self.redis_client, self.config.rate_limit_window_ms)
            
            # Initialize service discovery
            await self.service_discovery.initialize()
            
            logger.info("API Gateway initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize API Gateway: {e}")
            raise
    
    async def start(self):
        """Start API gateway server"""
        if self.running:
            return
        
        await self.initialize()
        
        # Start HTTP server (implementation would use aiohttp or similar)
        logger.info(f"API Gateway starting on {self.config.host}:{self.config.port}")
        self.running = True
        
        # In a real implementation, you would start the HTTP server here
        # For example, using aiohttp:
        # app = web.Application()
        # app.router.add_route('*', '/{path:.*}', self._handle_request)
        # runner = web.AppRunner(app)
        # await runner.setup()
        # site = web.TCPSite(runner, self.config.host, self.config.port)
        # await site.start()
    
    async def stop(self):
        """Stop API gateway"""
        self.running = False
        
        if self.redis_client:
            await self.redis_client.close()
        
        logger.info("API Gateway stopped")
    
    async def _handle_request(self, request):
        """Handle incoming HTTP request"""
        # Extract request information
        method = request.method
        path = request.path
        headers = dict(request.headers)
        body = await request.read()
        client_info = {
            'remote_addr': request.remote,
            'user_agent': headers.get('User-Agent', '')
        }
        
        # Process request through traffic manager
        status, response_headers, response_body = await self.traffic_manager.handle_request(
            method, path, headers, body, client_info
        )
        
        # Return response (implementation depends on web framework)
        return status, response_headers, response_body

# Global gateway instance
_gateway_instance = None

async def get_api_gateway(config: Optional[GatewayConfig] = None) -> APIGateway:
    """Get or create API gateway instance"""
    global _gateway_instance
    
    if _gateway_instance is None:
        if config is None:
            config = GatewayConfig()
        
        _gateway_instance = APIGateway(config)
        await _gateway_instance.start()
    
    return _gateway_instance

async def initialize_gateway(config: GatewayConfig) -> APIGateway:
    """Initialize API gateway with custom config"""
    gateway = APIGateway(config)
    await gateway.start()
    return gateway