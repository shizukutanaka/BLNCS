"""
Simple Rate Limiter for BLNCS
Lightweight rate limiting implementation
"""

import time
from typing import Dict, Optional
from collections import defaultdict, deque
import threading

class RateLimiter:
    """Token bucket rate limiter"""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        """
        Initialize rate limiter

        Args:
            max_requests: Maximum requests per window
            window_seconds: Time window in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def is_allowed(self, identifier: str) -> bool:
        """
        Check if request is allowed for identifier

        Args:
            identifier: Unique identifier (IP, user ID, etc.)

        Returns:
            True if allowed, False if rate limited
        """
        with self._lock:
            current_time = time.time()
            request_times = self.requests[identifier]

            # Remove old requests outside window
            while request_times and request_times[0] < current_time - self.window_seconds:
                request_times.popleft()

            # Check if under limit
            if len(request_times) < self.max_requests:
                request_times.append(current_time)
                return True

    def _fast_cleanup(self, identifier: str, current_time: float):
        """高速クリーンアップ"""
        request_times = self.requests[identifier]
        # 古いリクエストを効率的に削除
        while request_times and request_times[0] < current_time - self.window_seconds:
            request_times.popleft()

    def is_allowed_fast(self, identifier: str) -> bool:
        """高速レート制限チェック"""
        current_time = time.time()

        with self._lock:
            request_times = self.requests[identifier]
            self._fast_cleanup(identifier, current_time)

            # 高速チェック
            if len(request_times) < self.max_requests:
                request_times.append(current_time)
                return True

            return False

    def get_remaining_requests(self, identifier: str) -> int:
        """残りリクエスト数を取得"""
        with self._lock:
            current_time = time.time()
            request_times = self.requests[identifier]
            self._fast_cleanup(identifier, current_time)

            return max(0, self.max_requests - len(request_times))

    def get_reset_time(self, identifier: str) -> float:
        """レート制限リセット時間を取得"""
        with self._lock:
            request_times = self.requests[identifier]
            if not request_times:
                return 0.0

            return request_times[0] + self.window_seconds

    def get_rate_limit_status(self, identifier: str) -> Dict[str, Any]:
        """レート制限ステータスを取得"""
        with self._lock:
            current_time = time.time()
            request_times = self.requests[identifier]
            self._fast_cleanup(identifier, current_time)

            request_count = len(request_times)
            remaining = max(0, self.max_requests - request_count)
            reset_time = request_times[0] + self.window_seconds if request_times else 0

            return {
                'identifier': identifier,
                'requests_in_window': request_count,
                'max_requests': self.max_requests,
                'remaining_requests': remaining,
                'reset_time': reset_time,
                'is_limited': request_count >= self.max_requests
            }

    def reset_limit(self, identifier: str):
        """特定IDのレート制限をリセット"""
        with self._lock:
            if identifier in self.requests:
                self.requests[identifier].clear()

    def get_all_limit_status(self) -> Dict[str, Dict[str, Any]]:
        """全IDのレート制限ステータスを取得"""
        with self._lock:
            current_time = time.time()
            status = {}

            for identifier, request_times in self.requests.items():
                # クリーンアップ
                temp_times = deque(request_times)
                while temp_times and temp_times[0] < current_time - self.window_seconds:
                    temp_times.popleft()

                request_count = len(temp_times)
                remaining = max(0, self.max_requests - request_count)
                reset_time = temp_times[0] + self.window_seconds if temp_times else 0

                status[identifier] = {
                    'requests_in_window': request_count,
                    'remaining_requests': remaining,
                    'reset_time': reset_time,
                    'is_limited': request_count >= self.max_requests
                }

            return status

    def set_limit(self, max_requests: int, window_seconds: int):
        """レート制限パラメータを動的に変更"""
        with self._lock:
            self.max_requests = max_requests
            self.window_seconds = window_seconds

    def get_statistics(self) -> Dict[str, Any]:
        """レート制限統計を取得"""
        with self._lock:
            total_identifiers = len(self.requests)
            total_requests = sum(len(times) for times in self.requests.values())

            limited_identifiers = 0
            for identifier, request_times in self.requests.items():
                if len(request_times) >= self.max_requests:
                    limited_identifiers += 1

            return {
                'total_identifiers': total_identifiers,
                'total_requests': total_requests,
                'limited_identifiers': limited_identifiers,
                'max_requests_per_window': self.max_requests,
                'window_seconds': self.window_seconds
            }

    def remaining_requests(self, identifier: str) -> int:
        """Get remaining requests for identifier"""
        with self._lock:
            current_time = time.time()
            request_times = self.requests[identifier]

            # Remove old requests
            while request_times and request_times[0] < current_time - self.window_seconds:
                request_times.popleft()

            return max(0, self.max_requests - len(request_times))

    def reset_time(self, identifier: str) -> Optional[float]:
        """Get time until rate limit resets"""
        with self._lock:
            request_times = self.requests[identifier]
            if request_times:
                oldest = request_times[0]
                return max(0, self.window_seconds - (time.time() - oldest))
            return 0

    def clear(self, identifier: Optional[str] = None):
        """Clear rate limit history"""
        with self._lock:
            if identifier:
                self.requests.pop(identifier, None)
            else:
                self.requests.clear()

# Global rate limiter
_rate_limiter = None

def get_rate_limiter(max_requests: int = 60, window_seconds: int = 60) -> RateLimiter:
    """Get global rate limiter instance"""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter(max_requests, window_seconds)
    return _rate_limiter

# Flask decorator
def rate_limit(max_requests: int = 60, window_seconds: int = 60):
    """Decorator for Flask routes to add rate limiting"""
    def decorator(f):
        from functools import wraps
        from flask import request, jsonify

        @wraps(f)
        def wrapper(*args, **kwargs):
            # Get identifier (IP address)
            identifier = request.remote_addr

            # Check rate limit
            limiter = get_rate_limiter(max_requests, window_seconds)
            if not limiter.is_allowed(identifier):
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'retry_after': limiter.reset_time(identifier)
                }), 429

            # Add rate limit headers
            response = f(*args, **kwargs)
            if hasattr(response, 'headers'):
                response.headers['X-RateLimit-Limit'] = str(max_requests)
                response.headers['X-RateLimit-Remaining'] = str(limiter.remaining_requests(identifier))
                response.headers['X-RateLimit-Reset'] = str(int(time.time() + limiter.reset_time(identifier)))

            return response
        return wrapper
    return decorator

__all__ = ['RateLimiter', 'get_rate_limiter', 'rate_limit']