# BLRCS Rate Limiter Module
# Simple and efficient rate limiting
import time
from collections import defaultdict
from threading import Lock
from typing import Dict, Any

class RateLimiter:
    """Simple and efficient rate limiter using sliding window."""
    
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)
        self.lock = Lock()
    
    def check(self, identifier: str) -> bool:
        """Check if request is allowed."""
        current_time = time.time()
        window_start = current_time - self.window_seconds
        
        with self.lock:
            # Clean old requests
            self.requests[identifier] = [
                req_time for req_time in self.requests[identifier]
                if req_time > window_start
            ]
            
            # Check limit
            if len(self.requests[identifier]) >= self.max_requests:
                return False
            
            # Add current request
            self.requests[identifier].append(current_time)
            return True
    
    def get_status(self, identifier: str) -> Dict[str, Any]:
        """Get rate limit status for identifier"""
        current_time = time.time()
        window_start = current_time - self.window_seconds
        
        with self.lock:
            active_requests = [
                req_time for req_time in self.requests[identifier]
                if req_time > window_start
            ]
            
            remaining = max(0, self.max_requests - len(active_requests))
            reset_time = min(active_requests) + self.window_seconds if active_requests else current_time
            
            return {
                "limit": self.max_requests,
                "remaining": remaining,
                "reset": int(reset_time),
                "window": self.window_seconds
            }
    
    def cleanup(self):
        """Remove expired entries"""
        current_time = time.time()
        window_start = current_time - self.window_seconds
        
        with self.lock:
            expired = []
            for identifier, req_times in self.requests.items():
                self.requests[identifier] = [
                    t for t in req_times if t > window_start
                ]
                if not self.requests[identifier]:
                    expired.append(identifier)
            
            for identifier in expired:
                del self.requests[identifier]
