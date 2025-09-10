#!/usr/bin/env python3
"""
Comprehensive Rate Limiting and DDoS Protection System for BLNCS
Implements advanced rate limiting, request throttling, and abuse detection
"""

import asyncio
import hashlib
import ipaddress
import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Callable, Union, Tuple
import logging
import redis.asyncio as redis
from contextlib import asynccontextmanager
import weakref
import threading

from blncs.core.async_memory_manager import track_async_task, lightning_operation_context
from blncs.core.exceptions import BLNCSError

logger = logging.getLogger(__name__)

class RateLimitType(Enum):
    """Rate limit types"""
    PER_IP = "per_ip"
    PER_USER = "per_user"
    PER_ENDPOINT = "per_endpoint"
    GLOBAL = "global"
    SLIDING_WINDOW = "sliding_window"
    TOKEN_BUCKET = "token_bucket"

class ThreatLevel(Enum):
    """Threat assessment levels"""
    GREEN = "green"      # Normal traffic
    YELLOW = "yellow"    # Suspicious activity
    ORANGE = "orange"    # Likely attack
    RED = "red"          # Active attack
    CRITICAL = "critical" # DDoS attack

@dataclass
class RateLimitRule:
    """Rate limit rule configuration"""
    name: str
    limit_type: RateLimitType
    requests: int
    window_seconds: int
    burst_allowance: int = 0
    endpoints: List[str] = field(default_factory=list)
    user_types: List[str] = field(default_factory=list)
    enabled: bool = True
    penalty_seconds: int = 300  # 5 minutes default ban
    escalation_multiplier: float = 2.0

@dataclass
class ClientMetrics:
    """Client request metrics and behavior analysis"""
    client_id: str
    request_count: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    total_requests: int = 0
    blocked_requests: int = 0
    threat_score: float = 0.0
    threat_level: ThreatLevel = ThreatLevel.GREEN
    countries: Set[str] = field(default_factory=set)
    user_agents: Set[str] = field(default_factory=set)
    endpoints: Set[str] = field(default_factory=set)
    error_rate: float = 0.0
    ban_count: int = 0
    last_ban: Optional[float] = None

@dataclass
class RequestContext:
    """Request context for rate limiting"""
    client_ip: str
    user_id: Optional[str]
    endpoint: str
    method: str
    user_agent: Optional[str]
    country: Optional[str]
    timestamp: float = field(default_factory=time.time)
    headers: Dict[str, str] = field(default_factory=dict)
    request_size: int = 0

class TokenBucket:
    """Token bucket algorithm implementation"""
    
    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.tokens = float(capacity)
        self.refill_rate = refill_rate  # tokens per second
        self.last_refill = time.time()
        self._lock = threading.Lock()
    
    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens from bucket"""
        with self._lock:
            now = time.time()
            
            # Refill tokens based on elapsed time
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            self.last_refill = now
            
            # Check if enough tokens available
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            
            return False
    
    def get_wait_time(self, tokens: int = 1) -> float:
        """Get time to wait until enough tokens are available"""
        with self._lock:
            if self.tokens >= tokens:
                return 0.0
            
            needed_tokens = tokens - self.tokens
            return needed_tokens / self.refill_rate

class SlidingWindowCounter:
    """Sliding window rate limiter"""
    
    def __init__(self, window_size: int, max_requests: int):
        self.window_size = window_size
        self.max_requests = max_requests
        self.requests = deque()
        self._lock = threading.Lock()
    
    def allow_request(self, timestamp: Optional[float] = None) -> bool:
        """Check if request is allowed within sliding window"""
        if timestamp is None:
            timestamp = time.time()
        
        with self._lock:
            # Remove old requests outside window
            cutoff_time = timestamp - self.window_size
            while self.requests and self.requests[0] < cutoff_time:
                self.requests.popleft()
            
            # Check if under limit
            if len(self.requests) < self.max_requests:
                self.requests.append(timestamp)
                return True
            
            return False
    
    def get_reset_time(self) -> float:
        """Get time when oldest request will expire"""
        with self._lock:
            if not self.requests:
                return 0.0
            return self.requests[0] + self.window_size - time.time()

class ThreatDetector:
    """Advanced threat detection and analysis"""
    
    def __init__(self):
        self.client_profiles: Dict[str, ClientMetrics] = {}
        self.suspicious_patterns = {
            'rapid_requests': {'threshold': 100, 'window': 60},
            'error_spam': {'error_rate': 0.5, 'min_requests': 20},
            'endpoint_scanning': {'unique_endpoints': 50, 'window': 300},
            'user_agent_rotation': {'unique_agents': 10, 'window': 300}
        }
        self.geo_anomaly_threshold = 3  # Max countries per client
        self._lock = threading.RLock()
    
    def analyze_request(self, context: RequestContext, is_blocked: bool = False) -> ThreatLevel:
        """Analyze request and update threat assessment"""
        with self._lock:
            client_id = context.client_ip
            
            # Get or create client profile
            if client_id not in self.client_profiles:
                self.client_profiles[client_id] = ClientMetrics(client_id=client_id)
            
            profile = self.client_profiles[client_id]
            
            # Update metrics
            profile.request_count += 1
            profile.total_requests += 1
            profile.last_seen = context.timestamp
            
            if is_blocked:
                profile.blocked_requests += 1
            
            # Track behavioral patterns
            if context.country:
                profile.countries.add(context.country)
            if context.user_agent:
                profile.user_agents.add(context.user_agent)
            profile.endpoints.add(context.endpoint)
            
            # Calculate threat score
            threat_score = self._calculate_threat_score(profile, context)
            profile.threat_score = threat_score
            
            # Determine threat level
            if threat_score >= 90:
                profile.threat_level = ThreatLevel.CRITICAL
            elif threat_score >= 75:
                profile.threat_level = ThreatLevel.RED
            elif threat_score >= 50:
                profile.threat_level = ThreatLevel.ORANGE
            elif threat_score >= 25:
                profile.threat_level = ThreatLevel.YELLOW
            else:
                profile.threat_level = ThreatLevel.GREEN
            
            return profile.threat_level
    
    def _calculate_threat_score(self, profile: ClientMetrics, context: RequestContext) -> float:
        """Calculate comprehensive threat score"""
        score = 0.0
        now = context.timestamp
        
        # Request velocity (requests per minute)
        time_active = max(1, now - profile.first_seen)
        request_rate = profile.request_count / (time_active / 60)  # RPM
        
        if request_rate > 1000:  # > 1000 RPM is very suspicious
            score += 40
        elif request_rate > 500:
            score += 25
        elif request_rate > 100:
            score += 10
        
        # Error rate analysis
        if profile.total_requests > 10:
            profile.error_rate = profile.blocked_requests / profile.total_requests
            if profile.error_rate > 0.8:
                score += 30
            elif profile.error_rate > 0.5:
                score += 20
            elif profile.error_rate > 0.3:
                score += 10
        
        # Endpoint scanning behavior
        unique_endpoints = len(profile.endpoints)
        if unique_endpoints > 100:
            score += 25
        elif unique_endpoints > 50:
            score += 15
        elif unique_endpoints > 20:
            score += 5
        
        # User agent rotation (bot-like behavior)
        unique_agents = len(profile.user_agents)
        if unique_agents > 20:
            score += 20
        elif unique_agents > 10:
            score += 10
        elif unique_agents > 5:
            score += 5
        
        # Geographic anomalies
        unique_countries = len(profile.countries)
        if unique_countries > self.geo_anomaly_threshold:
            score += 15 * (unique_countries - self.geo_anomaly_threshold)
        
        # Previous ban history
        if profile.ban_count > 0:
            score += min(20, profile.ban_count * 5)
        
        # Recent ban penalty
        if profile.last_ban and (now - profile.last_ban) < 3600:  # Within last hour
            score += 15
        
        return min(100.0, score)
    
    def get_client_profile(self, client_id: str) -> Optional[ClientMetrics]:
        """Get client threat profile"""
        return self.client_profiles.get(client_id)
    
    def cleanup_old_profiles(self, max_age_seconds: int = 86400):
        """Clean up old client profiles"""
        now = time.time()
        cutoff = now - max_age_seconds
        
        with self._lock:
            to_remove = []
            for client_id, profile in self.client_profiles.items():
                if profile.last_seen < cutoff:
                    to_remove.append(client_id)
            
            for client_id in to_remove:
                del self.client_profiles[client_id]
            
            if to_remove:
                logger.info(f"Cleaned up {len(to_remove)} old client profiles")

class AdvancedRateLimiter:
    """Advanced rate limiting with multiple strategies"""
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis = redis_client
        self.rules: Dict[str, RateLimitRule] = {}
        self.token_buckets: Dict[str, TokenBucket] = {}
        self.sliding_windows: Dict[str, SlidingWindowCounter] = {}
        self.threat_detector = ThreatDetector()
        self.blocked_ips: Dict[str, float] = {}  # IP -> unblock_time
        self.whitelisted_ips: Set[str] = set()
        self.blacklisted_ips: Set[str] = set()
        self._lock = threading.RLock()
        
        # Setup default rules
        self._setup_default_rules()
        
        # Start cleanup task
        self._cleanup_task = None
    
    def _setup_default_rules(self):
        """Setup default rate limiting rules"""
        default_rules = [
            RateLimitRule(
                name="general_api",
                limit_type=RateLimitType.PER_IP,
                requests=1000,
                window_seconds=3600,  # 1000 requests per hour
                burst_allowance=50,
                penalty_seconds=600
            ),
            RateLimitRule(
                name="auth_endpoints",
                limit_type=RateLimitType.PER_IP,
                requests=10,
                window_seconds=300,   # 10 requests per 5 minutes
                endpoints=["/auth/login", "/auth/register", "/auth/reset"],
                penalty_seconds=900
            ),
            RateLimitRule(
                name="payment_endpoints",
                limit_type=RateLimitType.PER_USER,
                requests=100,
                window_seconds=3600,  # 100 payments per hour per user
                endpoints=["/api/payments", "/api/invoices"],
                penalty_seconds=1800
            ),
            RateLimitRule(
                name="ddos_protection",
                limit_type=RateLimitType.PER_IP,
                requests=50,
                window_seconds=60,    # 50 requests per minute
                burst_allowance=20,
                penalty_seconds=300
            )
        ]
        
        for rule in default_rules:
            self.add_rule(rule)
    
    def add_rule(self, rule: RateLimitRule):
        """Add rate limiting rule"""
        self.rules[rule.name] = rule
        logger.info(f"Added rate limit rule: {rule.name}")
    
    def add_to_whitelist(self, ip_address: str):
        """Add IP to whitelist"""
        self.whitelisted_ips.add(ip_address)
        logger.info(f"Added IP to whitelist: {ip_address}")
    
    def add_to_blacklist(self, ip_address: str, duration_seconds: int = 3600):
        """Add IP to blacklist"""
        self.blacklisted_ips.add(ip_address)
        if duration_seconds > 0:
            self.blocked_ips[ip_address] = time.time() + duration_seconds
        logger.warning(f"Added IP to blacklist: {ip_address}")
    
    @track_async_task("check_rate_limit")
    async def check_request(self, context: RequestContext) -> Tuple[bool, Dict[str, Any]]:
        """Check if request should be allowed"""
        async with lightning_operation_context("rate_limit_check"):
            # Check blacklist first
            if context.client_ip in self.blacklisted_ips:
                return False, {
                    'reason': 'blacklisted',
                    'retry_after': None,
                    'threat_level': 'critical'
                }
            
            # Check whitelist
            if context.client_ip in self.whitelisted_ips:
                return True, {'whitelisted': True}
            
            # Check temporary blocks
            if context.client_ip in self.blocked_ips:
                unblock_time = self.blocked_ips[context.client_ip]
                if time.time() < unblock_time:
                    return False, {
                        'reason': 'temporarily_blocked',
                        'retry_after': int(unblock_time - time.time()),
                        'threat_level': 'red'
                    }
                else:
                    # Remove expired block
                    del self.blocked_ips[context.client_ip]
            
            # Analyze threat level
            threat_level = self.threat_detector.analyze_request(context)
            
            # Apply rate limiting rules
            is_allowed = True
            limiting_rule = None
            retry_after = 0
            
            for rule_name, rule in self.rules.items():
                if not rule.enabled:
                    continue
                
                # Check if rule applies to this request
                if not self._rule_applies(rule, context):
                    continue
                
                # Check rate limit
                allowed, wait_time = await self._check_rule_limit(rule, context)
                
                if not allowed:
                    is_allowed = False
                    limiting_rule = rule_name
                    retry_after = max(retry_after, wait_time)
                    
                    # Apply penalty for repeated violations
                    self._apply_penalty(rule, context, threat_level)
                    break
            
            # Update threat analysis
            self.threat_detector.analyze_request(context, not is_allowed)
            
            result = {
                'allowed': is_allowed,
                'threat_level': threat_level.value,
                'limiting_rule': limiting_rule,
                'retry_after': retry_after
            }
            
            if not is_allowed:
                logger.warning(f"Rate limit exceeded for {context.client_ip}: {limiting_rule}")
            
            return is_allowed, result
    
    def _rule_applies(self, rule: RateLimitRule, context: RequestContext) -> bool:
        """Check if rule applies to the request"""
        # Check endpoint matching
        if rule.endpoints:
            if not any(endpoint in context.endpoint for endpoint in rule.endpoints):
                return False
        
        # Check user type matching (simplified - would check actual user type)
        if rule.user_types:
            # Would implement user type checking here
            pass
        
        return True
    
    async def _check_rule_limit(self, rule: RateLimitRule, context: RequestContext) -> Tuple[bool, int]:
        """Check specific rule limit"""
        # Generate key for this rule and context
        key_parts = [rule.name]
        
        if rule.limit_type == RateLimitType.PER_IP:
            key_parts.append(context.client_ip)
        elif rule.limit_type == RateLimitType.PER_USER and context.user_id:
            key_parts.append(context.user_id)
        elif rule.limit_type == RateLimitType.PER_ENDPOINT:
            key_parts.append(context.endpoint)
        
        key = ":".join(key_parts)
        
        if rule.limit_type == RateLimitType.TOKEN_BUCKET:
            return await self._check_token_bucket(key, rule)
        elif rule.limit_type == RateLimitType.SLIDING_WINDOW:
            return await self._check_sliding_window(key, rule, context.timestamp)
        else:
            # Default fixed window approach
            return await self._check_fixed_window(key, rule)
    
    async def _check_token_bucket(self, key: str, rule: RateLimitRule) -> Tuple[bool, int]:
        """Check token bucket rate limit"""
        if key not in self.token_buckets:
            # Create new token bucket
            capacity = rule.requests + rule.burst_allowance
            refill_rate = rule.requests / rule.window_seconds
            self.token_buckets[key] = TokenBucket(capacity, refill_rate)
        
        bucket = self.token_buckets[key]
        
        if bucket.consume(1):
            return True, 0
        else:
            wait_time = bucket.get_wait_time(1)
            return False, int(wait_time)
    
    async def _check_sliding_window(self, key: str, rule: RateLimitRule, timestamp: float) -> Tuple[bool, int]:
        """Check sliding window rate limit"""
        if key not in self.sliding_windows:
            self.sliding_windows[key] = SlidingWindowCounter(rule.window_seconds, rule.requests)
        
        window = self.sliding_windows[key]
        
        if window.allow_request(timestamp):
            return True, 0
        else:
            reset_time = window.get_reset_time()
            return False, int(reset_time)
    
    async def _check_fixed_window(self, key: str, rule: RateLimitRule) -> Tuple[bool, int]:
        """Check fixed window rate limit using Redis"""
        if not self.redis:
            # Fallback to memory-based limiting
            return await self._check_memory_window(key, rule)
        
        try:
            current_window = int(time.time() // rule.window_seconds)
            redis_key = f"rate_limit:{key}:{current_window}"
            
            # Increment counter
            count = await self.redis.incr(redis_key)
            
            # Set expiration on first increment
            if count == 1:
                await self.redis.expire(redis_key, rule.window_seconds)
            
            if count <= rule.requests:
                return True, 0
            else:
                # Calculate time until window resets
                next_window = (current_window + 1) * rule.window_seconds
                wait_time = int(next_window - time.time())
                return False, wait_time
        
        except Exception as e:
            logger.error(f"Redis rate limit check failed: {e}")
            return await self._check_memory_window(key, rule)
    
    async def _check_memory_window(self, key: str, rule: RateLimitRule) -> Tuple[bool, int]:
        """Memory-based fixed window rate limiting"""
        current_window = int(time.time() // rule.window_seconds)
        memory_key = f"{key}:{current_window}"
        
        with self._lock:
            if memory_key not in self.sliding_windows:
                # Use sliding window counter for memory implementation
                self.sliding_windows[memory_key] = SlidingWindowCounter(rule.window_seconds, rule.requests)
            
            window = self.sliding_windows[memory_key]
            
            if window.allow_request():
                return True, 0
            else:
                next_window = (current_window + 1) * rule.window_seconds
                wait_time = int(next_window - time.time())
                return False, wait_time
    
    def _apply_penalty(self, rule: RateLimitRule, context: RequestContext, threat_level: ThreatLevel):
        """Apply penalty for rate limit violation"""
        penalty_seconds = rule.penalty_seconds
        
        # Escalate penalty based on threat level
        if threat_level in [ThreatLevel.RED, ThreatLevel.CRITICAL]:
            penalty_seconds *= rule.escalation_multiplier
        elif threat_level == ThreatLevel.ORANGE:
            penalty_seconds *= 1.5
        
        # Apply temporary block
        unblock_time = time.time() + penalty_seconds
        self.blocked_ips[context.client_ip] = unblock_time
        
        # Update client profile
        profile = self.threat_detector.get_client_profile(context.client_ip)
        if profile:
            profile.ban_count += 1
            profile.last_ban = time.time()
        
        logger.warning(f"Applied {penalty_seconds}s penalty to {context.client_ip} (threat: {threat_level.value})")
    
    async def start_cleanup_task(self):
        """Start background cleanup task"""
        if not self._cleanup_task:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
    
    async def _cleanup_loop(self):
        """Background cleanup of expired data"""
        while True:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes
                
                # Clean up expired blocks
                now = time.time()
                expired_blocks = [ip for ip, unblock_time in self.blocked_ips.items() if now >= unblock_time]
                for ip in expired_blocks:
                    del self.blocked_ips[ip]
                
                # Clean up old token buckets and sliding windows
                with self._lock:
                    # Remove unused token buckets (simplified)
                    if len(self.token_buckets) > 10000:
                        # Keep only recent ones
                        recent_buckets = dict(list(self.token_buckets.items())[-5000:])
                        self.token_buckets = recent_buckets
                    
                    # Clean up old sliding windows
                    if len(self.sliding_windows) > 10000:
                        recent_windows = dict(list(self.sliding_windows.items())[-5000:])
                        self.sliding_windows = recent_windows
                
                # Clean up old threat profiles
                self.threat_detector.cleanup_old_profiles()
                
                logger.debug("Completed rate limiter cleanup")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get rate limiting statistics"""
        with self._lock:
            blocked_count = len(self.blocked_ips)
            active_buckets = len(self.token_buckets)
            active_windows = len(self.sliding_windows)
            client_profiles = len(self.threat_detector.client_profiles)
            
            # Threat level distribution
            threat_levels = defaultdict(int)
            for profile in self.threat_detector.client_profiles.values():
                threat_levels[profile.threat_level.value] += 1
            
            return {
                'blocked_ips': blocked_count,
                'whitelisted_ips': len(self.whitelisted_ips),
                'blacklisted_ips': len(self.blacklisted_ips),
                'active_token_buckets': active_buckets,
                'active_sliding_windows': active_windows,
                'client_profiles': client_profiles,
                'threat_level_distribution': dict(threat_levels),
                'rules_count': len(self.rules)
            }
    
    async def shutdown(self):
        """Shutdown rate limiter"""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        if self.redis:
            await self.redis.close()

# Factory function
async def create_rate_limiter(redis_url: Optional[str] = None) -> AdvancedRateLimiter:
    """Create advanced rate limiter with optional Redis backend"""
    redis_client = None
    
    if redis_url:
        try:
            redis_client = redis.from_url(redis_url)
            # Test connection
            await redis_client.ping()
            logger.info("Connected to Redis for rate limiting")
        except Exception as e:
            logger.warning(f"Failed to connect to Redis: {e}, using memory backend")
            redis_client = None
    
    limiter = AdvancedRateLimiter(redis_client)
    await limiter.start_cleanup_task()
    
    return limiter

# Middleware function for web frameworks
async def rate_limit_middleware(request, rate_limiter: AdvancedRateLimiter, 
                               get_client_ip: Callable, get_user_id: Callable = None):
    """Rate limiting middleware for web frameworks"""
    try:
        # Extract request context
        context = RequestContext(
            client_ip=get_client_ip(request),
            user_id=get_user_id(request) if get_user_id else None,
            endpoint=getattr(request, 'path', '/'),
            method=getattr(request, 'method', 'GET'),
            user_agent=getattr(request, 'headers', {}).get('user-agent'),
            headers=dict(getattr(request, 'headers', {})),
            request_size=len(getattr(request, 'body', b''))
        )
        
        # Check rate limit
        allowed, result = await rate_limiter.check_request(context)
        
        if not allowed:
            # Return rate limit exceeded response
            status_code = 429  # Too Many Requests
            response_data = {
                'error': 'Rate limit exceeded',
                'reason': result.get('reason', 'too_many_requests'),
                'retry_after': result.get('retry_after', 60),
                'threat_level': result.get('threat_level', 'unknown')
            }
            
            # Add rate limit headers
            headers = {
                'X-RateLimit-Limit': '1000',
                'X-RateLimit-Remaining': '0',
                'X-RateLimit-Reset': str(int(time.time()) + result.get('retry_after', 60)),
                'Retry-After': str(result.get('retry_after', 60))
            }
            
            return status_code, response_data, headers
        
        return None  # Allow request to proceed
        
    except Exception as e:
        logger.error(f"Rate limiting middleware error: {e}")
        return None  # Allow request on error to avoid breaking service

# Export main classes and functions
__all__ = [
    'RateLimitType',
    'ThreatLevel',
    'RateLimitRule',
    'ClientMetrics',
    'RequestContext',
    'TokenBucket',
    'SlidingWindowCounter',
    'ThreatDetector',
    'AdvancedRateLimiter',
    'create_rate_limiter',
    'rate_limit_middleware'
]