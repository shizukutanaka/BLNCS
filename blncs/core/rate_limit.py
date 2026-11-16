"""Token-bucket rate limiting.

Each client gets its own bucket: it holds up to ``burst_size`` tokens
and refills at ``requests_per_second``. A per-minute ceiling
(``requests_per_minute``) is enforced on top of the bucket so a client
cannot sustain more than that rate over a full minute either.
"""

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class RateLimitConfig:
    """Rate limit parameters."""

    requests_per_second: float = 5
    requests_per_minute: int = 100
    burst_size: int = 10


@dataclass
class _Bucket:
    tokens: float
    last_refill: float
    minute_window_start: float
    minute_count: int = 0


class RateLimiter:
    """Per-client token-bucket rate limiter."""

    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self._buckets: Dict[str, _Bucket] = {}
        self._lock = threading.Lock()
        self._total_allowed = 0
        self._total_blocked = 0

    def _bucket_for(self, client_id: str, now: float) -> _Bucket:
        bucket = self._buckets.get(client_id)
        if bucket is None:
            bucket = _Bucket(
                tokens=float(self.config.burst_size),
                last_refill=now,
                minute_window_start=now,
            )
            self._buckets[client_id] = bucket
        return bucket

    def check_rate_limit(self, client_id: Optional[str] = None) -> bool:
        """Return True when the request is allowed for this client."""
        key = client_id if client_id is not None else "__default__"
        now = time.monotonic()
        with self._lock:
            bucket = self._bucket_for(key, now)

            # Refill the bucket based on elapsed time.
            elapsed = now - bucket.last_refill
            bucket.tokens = min(
                float(self.config.burst_size),
                bucket.tokens + elapsed * self.config.requests_per_second,
            )
            bucket.last_refill = now

            # Reset the per-minute window when it has elapsed.
            if now - bucket.minute_window_start >= 60:
                bucket.minute_window_start = now
                bucket.minute_count = 0

            allowed = (
                bucket.tokens >= 1.0
                and bucket.minute_count < self.config.requests_per_minute
            )
            if allowed:
                bucket.tokens -= 1.0
                bucket.minute_count += 1
                self._total_allowed += 1
            else:
                self._total_blocked += 1
            return allowed

    def get_stats(self) -> Dict[str, Any]:
        """Return limiter statistics."""
        with self._lock:
            return {
                "total_allowed": self._total_allowed,
                "total_blocked": self._total_blocked,
                "tracked_clients": len(self._buckets),
            }
