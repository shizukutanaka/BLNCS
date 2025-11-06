#!/usr/bin/env python3
"""
Advanced API Rate Limiting Module
Implements Token Bucket, Leaky Bucket, and Sliding Window algorithms
Based on 2025 research on distributed rate limiting strategies
"""

import logging
import time
import asyncio
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class RateLimitStrategy(Enum):
    """Rate limiting algorithm strategies"""
    TOKEN_BUCKET = "token_bucket"
    LEAKY_BUCKET = "leaky_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting"""
    requests_per_second: float = 10.0
    burst_capacity: int = 100
    window_size_seconds: int = 60
    strategy: RateLimitStrategy = RateLimitStrategy.TOKEN_BUCKET
    enable_dynamic_adjustment: bool = True


@dataclass
class RateLimitMetrics:
    """Metrics for rate limiting"""
    total_requests: int = 0
    allowed_requests: int = 0
    rejected_requests: int = 0
    current_rate: float = 0.0
    rejection_rate: float = 0.0
    avg_wait_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'total_requests': self.total_requests,
            'allowed_requests': self.allowed_requests,
            'rejected_requests': self.rejected_requests,
            'current_rate': self.current_rate,
            'rejection_rate': self.rejection_rate,
            'avg_wait_time_ms': self.avg_wait_time_ms
        }


class TokenBucketLimiter:
    """
    Token Bucket rate limiter
    Allows bursts up to bucket capacity, refills at constant rate
    """

    def __init__(self, rate: float, capacity: int):
        """
        Initialize token bucket

        Args:
            rate: Tokens added per second
            capacity: Maximum tokens in bucket
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_refill = time.time()

    def allow_request(self, tokens: int = 1) -> bool:
        """
        Check if request should be allowed

        Args:
            tokens: Tokens required for this request

        Returns:
            True if request allowed, False otherwise
        """
        self._refill()

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True

        return False

    def _refill(self) -> None:
        """Refill tokens based on elapsed time"""
        now = time.time()
        elapsed = now - self.last_refill

        tokens_to_add = elapsed * self.rate
        self.tokens = min(self.capacity, self.tokens + tokens_to_add)
        self.last_refill = now

    def get_wait_time(self, tokens: int = 1) -> float:
        """Get wait time before request is allowed (in seconds)"""
        self._refill()

        if self.tokens >= tokens:
            return 0.0

        needed = tokens - self.tokens
        return needed / self.rate


class LeakyBucketLimiter:
    """
    Leaky Bucket rate limiter
    Processes requests at constant rate, queues excess
    """

    def __init__(self, rate: float, capacity: int):
        """
        Initialize leaky bucket

        Args:
            rate: Requests processed per second
            capacity: Maximum queue size
        """
        self.rate = rate
        self.capacity = capacity
        self.queue: deque = deque()
        self.last_drain = time.time()

    def allow_request(self) -> bool:
        """
        Check if request can be queued

        Returns:
            True if queued successfully, False if queue full
        """
        self._drain()

        if len(self.queue) < self.capacity:
            self.queue.append(time.time())
            return True

        return False

    def _drain(self) -> None:
        """Drain processed requests from queue"""
        now = time.time()
        elapsed = now - self.last_drain

        requests_to_drain = int(elapsed * self.rate)

        for _ in range(requests_to_drain):
            if self.queue:
                self.queue.popleft()

        self.last_drain = now

    def get_queue_length(self) -> int:
        """Get current queue length"""
        self._drain()
        return len(self.queue)


class SlidingWindowLimiter:
    """
    Sliding Window rate limiter
    Tracks requests in a time window, fair distribution
    """

    def __init__(self, requests_per_window: int, window_seconds: int):
        """
        Initialize sliding window

        Args:
            requests_per_window: Max requests in window
            window_seconds: Window size in seconds
        """
        self.max_requests = requests_per_window
        self.window_seconds = window_seconds
        self.request_times: List[float] = []

    def allow_request(self) -> bool:
        """
        Check if request allowed within window

        Returns:
            True if request allowed, False if limit exceeded
        """
        now = time.time()
        window_start = now - self.window_seconds

        # Remove old requests outside window
        self.request_times = [t for t in self.request_times if t > window_start]

        if len(self.request_times) < self.max_requests:
            self.request_times.append(now)
            return True

        return False

    def get_requests_in_window(self) -> int:
        """Get number of requests in current window"""
        now = time.time()
        window_start = now - self.window_seconds
        return len([t for t in self.request_times if t > window_start])


class FixedWindowLimiter:
    """
    Fixed Window rate limiter
    Simple counter reset per time window
    """

    def __init__(self, requests_per_window: int, window_seconds: int):
        """
        Initialize fixed window

        Args:
            requests_per_window: Max requests per window
            window_seconds: Window size in seconds
        """
        self.max_requests = requests_per_window
        self.window_seconds = window_seconds
        self.window_start = time.time()
        self.request_count = 0

    def allow_request(self) -> bool:
        """
        Check if request allowed in current window

        Returns:
            True if request allowed, False if limit exceeded
        """
        now = time.time()
        elapsed = now - self.window_start

        # Reset window if expired
        if elapsed >= self.window_seconds:
            self.window_start = now
            self.request_count = 0

        if self.request_count < self.max_requests:
            self.request_count += 1
            return True

        return False

    def get_window_reset_time(self) -> float:
        """Get seconds until window resets"""
        now = time.time()
        elapsed = now - self.window_start
        return max(0, self.window_seconds - elapsed)


class RateLimiter:
    """
    Unified rate limiter with multiple strategies and per-client tracking
    """

    def __init__(self, config: RateLimitConfig):
        """Initialize rate limiter"""
        self.config = config
        self.limiters: Dict[str, object] = {}
        self.metrics: Dict[str, RateLimitMetrics] = defaultdict(RateLimitMetrics)
        self.wait_times: List[float] = []

    def check_limit(self, client_id: str) -> Tuple[bool, Optional[float]]:
        """
        Check if request is allowed for client

        Args:
            client_id: Unique client identifier

        Returns:
            Tuple of (allowed, wait_time_seconds)
        """
        if client_id not in self.limiters:
            self._create_limiter(client_id)

        limiter = self.limiters[client_id]
        metrics = self.metrics[client_id]
        metrics.total_requests += 1

        allowed = False
        wait_time = 0.0

        # Execute based on strategy
        if self.config.strategy == RateLimitStrategy.TOKEN_BUCKET:
            allowed = limiter.allow_request()
            if not allowed:
                wait_time = limiter.get_wait_time()

        elif self.config.strategy == RateLimitStrategy.LEAKY_BUCKET:
            allowed = limiter.allow_request()
            if not allowed:
                wait_time = 5.0  # Queue wait estimate

        elif self.config.strategy == RateLimitStrategy.SLIDING_WINDOW:
            allowed = limiter.allow_request()
            wait_time = 0.0 if allowed else 1.0

        elif self.config.strategy == RateLimitStrategy.FIXED_WINDOW:
            allowed = limiter.allow_request()
            if not allowed:
                wait_time = limiter.get_window_reset_time()

        # Update metrics
        if allowed:
            metrics.allowed_requests += 1
        else:
            metrics.rejected_requests += 1

        if wait_time > 0:
            self.wait_times.append(wait_time)
            if len(self.wait_times) > 1000:
                self.wait_times = self.wait_times[-1000:]

        self._update_metrics(metrics)

        logger.debug(
            f"Client {client_id}: {'ALLOWED' if allowed else 'REJECTED'} "
            f"(wait: {wait_time:.2f}s)"
        )

        return allowed, wait_time if not allowed else None

    def _create_limiter(self, client_id: str) -> None:
        """Create appropriate limiter for client"""
        rate = self.config.requests_per_second

        if self.config.strategy == RateLimitStrategy.TOKEN_BUCKET:
            self.limiters[client_id] = TokenBucketLimiter(
                rate, self.config.burst_capacity
            )

        elif self.config.strategy == RateLimitStrategy.LEAKY_BUCKET:
            self.limiters[client_id] = LeakyBucketLimiter(
                rate, self.config.burst_capacity
            )

        elif self.config.strategy == RateLimitStrategy.SLIDING_WINDOW:
            requests = int(rate * self.config.window_size_seconds)
            self.limiters[client_id] = SlidingWindowLimiter(
                requests, self.config.window_size_seconds
            )

        elif self.config.strategy == RateLimitStrategy.FIXED_WINDOW:
            requests = int(rate * self.config.window_size_seconds)
            self.limiters[client_id] = FixedWindowLimiter(
                requests, self.config.window_size_seconds
            )

    def _update_metrics(self, metrics: RateLimitMetrics) -> None:
        """Update metrics calculations"""
        total = metrics.total_requests
        if total > 0:
            metrics.rejection_rate = (metrics.rejected_requests / total) * 100
            metrics.current_rate = metrics.allowed_requests / total

        if self.wait_times:
            metrics.avg_wait_time_ms = (sum(self.wait_times) / len(self.wait_times)) * 1000

    def get_metrics(self, client_id: str) -> Optional[RateLimitMetrics]:
        """Get metrics for specific client"""
        return self.metrics.get(client_id)

    def get_all_metrics(self) -> Dict[str, RateLimitMetrics]:
        """Get all client metrics"""
        return dict(self.metrics)

    async def throttle(self, client_id: str, max_wait: float = 30.0) -> None:
        """
        Async throttle - wait if needed

        Args:
            client_id: Client identifier
            max_wait: Maximum wait time in seconds

        Raises:
            RuntimeError: If wait exceeds max_wait
        """
        allowed, wait_time = self.check_limit(client_id)

        if not allowed and wait_time:
            if wait_time > max_wait:
                raise RuntimeError(
                    f"Rate limit exceeded. Required wait: {wait_time:.2f}s, "
                    f"max allowed: {max_wait:.2f}s"
                )
            await asyncio.sleep(wait_time)


__all__ = [
    'RateLimitStrategy',
    'RateLimitConfig',
    'RateLimitMetrics',
    'TokenBucketLimiter',
    'LeakyBucketLimiter',
    'SlidingWindowLimiter',
    'FixedWindowLimiter',
    'RateLimiter',
]
