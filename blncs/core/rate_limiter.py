"""
Lightweight Rate Limiting System
Memory-based rate limiting for API protection.
"""

import time
import threading
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum
from functools import wraps

from .logger import get_logger

logger = get_logger(__name__)

class RateLimitStrategy(Enum):
    """Rate limiting strategies."""
    FIXED_WINDOW = "fixed_window"
    SLIDING_WINDOW = "sliding_window" 
    TOKEN_BUCKET = "token_bucket"

@dataclass
class RateLimit:
    """Rate limit configuration."""
    requests: int
    window_seconds: int
    strategy: RateLimitStrategy = RateLimitStrategy.SLIDING_WINDOW
    burst_requests: Optional[int] = None  # For token bucket

@dataclass
class RateLimitState:
    """Rate limit state for a key."""
    requests: deque = field(default_factory=deque)
    tokens: float = 0.0
    last_refill: float = field(default_factory=time.time)
    blocked_until: float = 0.0

class RateLimiter:
    """Lightweight rate limiter."""
    
    def __init__(self, default_limit: Optional[RateLimit] = None):
        """Initialize rate limiter."""
        self.logger = get_logger(__name__)
        self.default_limit = default_limit or RateLimit(requests=100, window_seconds=60)
        self.limits: Dict[str, RateLimit] = {}
        self.state: Dict[str, RateLimitState] = defaultdict(RateLimitState)
        self.lock = threading.RLock()
        
        # Cleanup old entries periodically
        self._last_cleanup = time.time()
        self._cleanup_interval = 300  # 5 minutes
    
    def set_limit(self, key: str, limit: RateLimit):
        """Set rate limit for specific key."""
        with self.lock:
            self.limits[key] = limit
            
    def _cleanup_old_entries(self):
        """Remove old state entries to prevent memory leaks."""
        current_time = time.time()
        if current_time - self._last_cleanup < self._cleanup_interval:
            return
            
        with self.lock:
            keys_to_remove = []
            
            for key, state in self.state.items():
                # Remove entries that haven't been accessed recently
                if (not state.requests and 
                    current_time - state.last_refill > self._cleanup_interval * 2):
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                del self.state[key]
                
            self._last_cleanup = current_time
            
            if keys_to_remove:
                self.logger.debug(f"Cleaned up {len(keys_to_remove)} old rate limit entries")
    
    def _check_sliding_window(self, key: str, limit: RateLimit) -> bool:
        """Check sliding window rate limit."""
        current_time = time.time()
        state = self.state[key]
        
        # Remove old requests outside the window
        cutoff_time = current_time - limit.window_seconds
        while state.requests and state.requests[0] <= cutoff_time:
            state.requests.popleft()
        
        # Check if we're under the limit
        if len(state.requests) < limit.requests:
            state.requests.append(current_time)
            return True
        
        return False
    
    def _check_fixed_window(self, key: str, limit: RateLimit) -> bool:
        """Check fixed window rate limit."""
        current_time = time.time()
        state = self.state[key]
        
        # Calculate current window start
        window_start = int(current_time / limit.window_seconds) * limit.window_seconds
        
        # Reset counter if we're in a new window
        if not state.requests or state.requests[0] < window_start:
            state.requests.clear()
        
        # Check if we're under the limit
        if len(state.requests) < limit.requests:
            state.requests.append(current_time)
            return True
        
        return False
    
    def _check_token_bucket(self, key: str, limit: RateLimit) -> bool:
        """Check token bucket rate limit."""
        current_time = time.time()
        state = self.state[key]
        
        # Initialize tokens if first request
        if state.tokens == 0 and state.last_refill == 0:
            state.tokens = limit.burst_requests or limit.requests
            state.last_refill = current_time
        
        # Refill tokens based on elapsed time
        elapsed = current_time - state.last_refill
        tokens_to_add = elapsed * (limit.requests / limit.window_seconds)
        state.tokens = min(limit.burst_requests or limit.requests, 
                          state.tokens + tokens_to_add)
        state.last_refill = current_time
        
        # Check if we have tokens available
        if state.tokens >= 1.0:
            state.tokens -= 1.0
            return True
        
        return False
    
    def is_allowed(self, key: str, limit_key: Optional[str] = None) -> bool:
        """Check if request is allowed."""
        with self.lock:
            # Periodic cleanup
            self._cleanup_old_entries()
            
            # Get the appropriate limit
            limit = self.limits.get(limit_key, self.default_limit)
            
            # Check if currently blocked
            current_time = time.time()
            state = self.state[key]
            if state.blocked_until > current_time:
                return False
            
            # Apply rate limiting strategy
            if limit.strategy == RateLimitStrategy.SLIDING_WINDOW:
                allowed = self._check_sliding_window(key, limit)
            elif limit.strategy == RateLimitStrategy.FIXED_WINDOW:
                allowed = self._check_fixed_window(key, limit)
            elif limit.strategy == RateLimitStrategy.TOKEN_BUCKET:
                allowed = self._check_token_bucket(key, limit)
            else:
                allowed = True  # Unknown strategy, allow by default
            
            if not allowed:
                self.logger.debug(f"Rate limit exceeded for key: {key}")
            
            return allowed
    
    def block_key(self, key: str, duration_seconds: int):
        """Block a key for specified duration."""
        with self.lock:
            self.state[key].blocked_until = time.time() + duration_seconds
            self.logger.info(f"Blocked key '{key}' for {duration_seconds} seconds")
    
    def unblock_key(self, key: str):
        """Unblock a key."""
        with self.lock:
            self.state[key].blocked_until = 0
            self.logger.info(f"Unblocked key: {key}")
    
    def get_remaining_requests(self, key: str, limit_key: Optional[str] = None) -> int:
        """Get remaining requests for a key."""
        with self.lock:
            limit = self.limits.get(limit_key, self.default_limit)
            state = self.state[key]
            
            if limit.strategy == RateLimitStrategy.SLIDING_WINDOW:
                current_time = time.time()
                cutoff_time = current_time - limit.window_seconds
                
                # Count requests in current window
                current_requests = sum(1 for req_time in state.requests 
                                     if req_time > cutoff_time)
                return max(0, limit.requests - current_requests)
                
            elif limit.strategy == RateLimitStrategy.TOKEN_BUCKET:
                return int(state.tokens)
                
            else:  # Fixed window
                return max(0, limit.requests - len(state.requests))
    
    def get_reset_time(self, key: str, limit_key: Optional[str] = None) -> float:
        """Get time when rate limit resets."""
        with self.lock:
            limit = self.limits.get(limit_key, self.default_limit)
            state = self.state[key]
            current_time = time.time()
            
            if limit.strategy == RateLimitStrategy.SLIDING_WINDOW:
                if state.requests:
                    return state.requests[0] + limit.window_seconds
                return current_time
                
            elif limit.strategy == RateLimitStrategy.FIXED_WINDOW:
                window_start = int(current_time / limit.window_seconds) * limit.window_seconds
                return window_start + limit.window_seconds
                
            else:  # Token bucket
                if state.tokens < 1.0:
                    tokens_needed = 1.0 - state.tokens
                    time_needed = tokens_needed / (limit.requests / limit.window_seconds)
                    return current_time + time_needed
                return current_time
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics."""
        with self.lock:
            current_time = time.time()
            active_keys = 0
            blocked_keys = 0
            
            for state in self.state.values():
                if state.requests or state.blocked_until > current_time:
                    active_keys += 1
                if state.blocked_until > current_time:
                    blocked_keys += 1
            
            return {
                "total_keys": len(self.state),
                "active_keys": active_keys,
                "blocked_keys": blocked_keys,
                "configured_limits": len(self.limits),
                "default_limit": {
                    "requests": self.default_limit.requests,
                    "window_seconds": self.default_limit.window_seconds,
                    "strategy": self.default_limit.strategy.value
                }
            }

# Decorator for rate limiting functions
def rate_limit(requests: int = 100, window_seconds: int = 60, 
               key_func: Optional[Callable] = None,
               strategy: RateLimitStrategy = RateLimitStrategy.SLIDING_WINDOW):
    """Decorator to rate limit function calls."""
    
    def decorator(func: Callable) -> Callable:
        # Create a rate limiter instance for this function
        limiter = RateLimiter(RateLimit(requests, window_seconds, strategy))
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Determine the key for rate limiting
            if key_func:
                key = key_func(*args, **kwargs)
            else:
                # Default: use function name and first argument (if any)
                key = f"{func.__name__}:{args[0] if args else 'default'}"
            
            # Check rate limit
            if not limiter.is_allowed(key):
                remaining = limiter.get_remaining_requests(key)
                reset_time = limiter.get_reset_time(key)
                
                raise RateLimitExceeded(
                    f"Rate limit exceeded for {key}. "
                    f"Remaining: {remaining}, Reset: {reset_time}"
                )
            
            return func(*args, **kwargs)
        
        # Add rate limiter methods to the wrapper
        wrapper.rate_limiter = limiter
        return wrapper
    
    return decorator

class RateLimitExceeded(Exception):
    """Rate limit exceeded exception."""
    pass

# Global rate limiter instances
default_rate_limiter = RateLimiter()
api_rate_limiter = RateLimiter(RateLimit(requests=50, window_seconds=60))

def get_rate_limiter(name: str = "default") -> RateLimiter:
    """Get rate limiter by name."""
    limiters = {
        "default": default_rate_limiter,
        "api": api_rate_limiter
    }
    return limiters.get(name, default_rate_limiter)

if __name__ == "__main__":
    # Test the rate limiter
    limiter = RateLimiter(RateLimit(requests=5, window_seconds=10))
    
    # Test requests
    key = "test_user"
    for i in range(7):
        allowed = limiter.is_allowed(key)
        remaining = limiter.get_remaining_requests(key)
        print(f"Request {i+1}: Allowed={allowed}, Remaining={remaining}")
        
        if allowed:
            time.sleep(0.5)
    
    print(f"Stats: {limiter.get_stats()}")