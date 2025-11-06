"""
Smart Connection Retry Logic for BLNCS
指数バックオフとサーキットブレーカーパターン実装
"""

import time
import random
import threading
from typing import Callable, Any, Optional, Dict, List
from dataclasses import dataclass
from enum import Enum
import logging
from functools import wraps


class ConnectionState(Enum):
    """Connection state"""
    CLOSED = "closed"
    HALF_OPEN = "half_open"
    OPEN = "open"


@dataclass
class RetryConfig:
    """Retry configuration"""
    max_attempts: int = 5
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True
    timeout: float = 30.0


@dataclass
class RetryResult:
    """Retry operation result"""
    success: bool
    attempts: int
    total_time: float
    last_error: Optional[str] = None
    circuit_breaker_triggered: bool = False


class CircuitBreaker:
    """Circuit breaker for connection reliability"""

    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 60.0):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = ConnectionState.CLOSED
        self.lock = threading.RLock()

    def can_execute(self) -> bool:
        """Check if execution is allowed"""
        with self.lock:
            if self.state == ConnectionState.CLOSED:
                return True
            elif self.state == ConnectionState.OPEN:
                if time.time() - self.last_failure_time >= self.recovery_timeout:
                    self.state = ConnectionState.HALF_OPEN
                    return True
                return False
            else:  # HALF_OPEN
                return True

    def record_success(self):
        """Record successful operation"""
        with self.lock:
            self.failure_count = 0
            self.state = ConnectionState.CLOSED

    def record_failure(self):
        """Record failed operation"""
        with self.lock:
            self.failure_count += 1
            self.last_failure_time = time.time()

            if self.failure_count >= self.failure_threshold:
                self.state = ConnectionState.OPEN


class SmartRetry:
    """Smart retry logic with exponential backoff"""

    def __init__(self, config: Optional[RetryConfig] = None):
        self.config = config or RetryConfig()
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.stats: Dict[str, Dict[str, Any]] = {}
        self.logger = logging.getLogger(__name__)

    def get_circuit_breaker(self, name: str) -> CircuitBreaker:
        """Get or create circuit breaker for named connection"""
        if name not in self.circuit_breakers:
            self.circuit_breakers[name] = CircuitBreaker()
        return self.circuit_breakers[name]

    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay for retry attempt"""
        delay = self.config.base_delay * (self.config.exponential_base ** (attempt - 1))
        delay = min(delay, self.config.max_delay)

        # Add jitter to prevent thundering herd
        if self.config.jitter:
            jitter = random.uniform(0.1, 0.9) * delay
            delay = delay * 0.5 + jitter

        return delay

    def retry_with_backoff(self, func: Callable, *args, **kwargs) -> RetryResult:
        """Execute function with retry and backoff"""
        func_name = getattr(func, '__name__', 'unknown')
        circuit_breaker = self.get_circuit_breaker(func_name)

        start_time = time.time()
        last_error = None
        attempts = 0

        # Initialize stats if not exists
        if func_name not in self.stats:
            self.stats[func_name] = {
                'total_calls': 0,
                'successful_calls': 0,
                'failed_calls': 0,
                'total_attempts': 0,
                'circuit_breaker_trips': 0
            }

        stats = self.stats[func_name]
        stats['total_calls'] += 1

        # Check circuit breaker
        if not circuit_breaker.can_execute():
            stats['circuit_breaker_trips'] += 1
            return RetryResult(
                success=False,
                attempts=0,
                total_time=time.time() - start_time,
                last_error="Circuit breaker open",
                circuit_breaker_triggered=True
            )

        for attempt in range(1, self.config.max_attempts + 1):
            attempts = attempt
            stats['total_attempts'] += 1

            try:
                # Set timeout for the operation
                result = func(*args, **kwargs)
                circuit_breaker.record_success()
                stats['successful_calls'] += 1

                return RetryResult(
                    success=True,
                    attempts=attempts,
                    total_time=time.time() - start_time,
                    circuit_breaker_triggered=False
                )

            except Exception as e:
                last_error = str(e)
                circuit_breaker.record_failure()

                self.logger.warning(f"Attempt {attempt}/{self.config.max_attempts} failed for {func_name}: {e}")

                # Don't delay on last attempt
                if attempt < self.config.max_attempts:
                    delay = self.calculate_delay(attempt)
                    time.sleep(delay)

        # All attempts failed
        stats['failed_calls'] += 1
        return RetryResult(
            success=False,
            attempts=attempts,
            total_time=time.time() - start_time,
            last_error=last_error,
            circuit_breaker_triggered=False
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get retry statistics"""
        return dict(self.stats)

    def reset_stats(self):
        """Reset statistics"""
        self.stats.clear()

    def reset_circuit_breaker(self, name: str):
        """Reset specific circuit breaker"""
        if name in self.circuit_breakers:
            breaker = self.circuit_breakers[name]
            with breaker.lock:
                breaker.failure_count = 0
                breaker.state = ConnectionState.CLOSED


def retry_on_failure(config: Optional[RetryConfig] = None, circuit_breaker_name: Optional[str] = None):
    """Decorator for automatic retry with backoff"""
    def decorator(func: Callable) -> Callable:
        retry_logic = SmartRetry(config)
        breaker_name = circuit_breaker_name or func.__name__

        @wraps(func)
        def wrapper(*args, **kwargs):
            result = retry_logic.retry_with_backoff(func, *args, **kwargs)

            if result.success:
                return func(*args, **kwargs)  # Return actual result
            else:
                if result.circuit_breaker_triggered:
                    raise ConnectionError(f"Circuit breaker open for {breaker_name}")
                else:
                    raise ConnectionError(f"Max retries exceeded: {result.last_error}")

        # Add retry stats to wrapper
        wrapper.get_retry_stats = lambda: retry_logic.get_stats()
        wrapper.reset_retry_stats = retry_logic.reset_stats
        return wrapper
    return decorator


class ConnectionPool:
    """Simple connection pool with retry logic"""

    def __init__(self, create_connection: Callable, max_connections: int = 10):
        self.create_connection = create_connection
        self.max_connections = max_connections
        self.connections: List[Any] = []
        self.in_use: List[Any] = []
        self.lock = threading.RLock()
        self.retry_logic = SmartRetry()

    def get_connection(self) -> Any:
        """Get connection from pool with retry"""
        with self.lock:
            # Try to reuse existing connection
            if self.connections:
                conn = self.connections.pop()
                self.in_use.append(conn)
                return conn

            # Create new connection if under limit
            if len(self.in_use) < self.max_connections:
                result = self.retry_logic.retry_with_backoff(self.create_connection)
                if result.success:
                    conn = self.create_connection()
                    self.in_use.append(conn)
                    return conn
                else:
                    raise ConnectionError(f"Failed to create connection: {result.last_error}")

            raise ConnectionError("Connection pool exhausted")

    def return_connection(self, conn: Any):
        """Return connection to pool"""
        with self.lock:
            if conn in self.in_use:
                self.in_use.remove(conn)
                # Simple validation - check if connection is still valid
                try:
                    if hasattr(conn, 'ping'):
                        conn.ping()
                    self.connections.append(conn)
                except:
                    # Connection is bad, don't return to pool
                    pass

    def close_all(self):
        """Close all connections"""
        with self.lock:
            all_connections = self.connections + self.in_use
            for conn in all_connections:
                try:
                    if hasattr(conn, 'close'):
                        conn.close()
                except:
                    pass
            self.connections.clear()
            self.in_use.clear()


# Enhanced Lightning client with retry
class ReliableLightningClient:
    """Lightning client with built-in retry and circuit breaker"""

    def __init__(self, base_client_class, *args, **kwargs):
        self.base_client = base_client_class(*args, **kwargs)
        self.retry_config = RetryConfig(max_attempts=3, base_delay=2.0)
        self.retry_logic = SmartRetry(self.retry_config)

    @retry_on_failure(RetryConfig(max_attempts=3, base_delay=1.0))
    def connect(self):
        """Connect with retry logic"""
        return self.base_client.connect()

    @retry_on_failure(RetryConfig(max_attempts=2, base_delay=0.5))
    def get_info(self):
        """Get info with retry"""
        if not self.base_client.connected:
            self.connect()
        return self.base_client.get_info()

    @retry_on_failure(RetryConfig(max_attempts=2, base_delay=0.5))
    def get_balance(self):
        """Get balance with retry"""
        if not self.base_client.connected:
            self.connect()
        return self.base_client.get_balance()

    @retry_on_failure(RetryConfig(max_attempts=3, base_delay=1.0))
    def create_invoice(self, amount: int, memo: str = ""):
        """Create invoice with retry"""
        if not self.base_client.connected:
            self.connect()
        return self.base_client.create_invoice(amount, memo)

    @retry_on_failure(RetryConfig(max_attempts=1, base_delay=5.0))  # Payments are critical
    def pay_invoice(self, payment_request: str):
        """Pay invoice with limited retry (dangerous to retry payments)"""
        if not self.base_client.connected:
            self.connect()
        return self.base_client.pay_invoice(payment_request)

    def disconnect(self):
        """Disconnect (no retry needed)"""
        return self.base_client.disconnect()

    def get_retry_stats(self) -> Dict[str, Any]:
        """Get retry statistics"""
        return self.retry_logic.get_stats()


# Global retry instance
_global_retry = SmartRetry()


def get_global_retry() -> SmartRetry:
    """Get global retry instance"""
    return _global_retry


def create_reliable_lightning_client():
    """Create Lightning client with retry logic"""
    from blncs.lightning.simple_client import SimpleLightningClient
    return ReliableLightningClient(SimpleLightningClient)


__all__ = [
    'SmartRetry', 'RetryConfig', 'RetryResult', 'CircuitBreaker',
    'ConnectionPool', 'ReliableLightningClient',
    'retry_on_failure', 'get_global_retry', 'create_reliable_lightning_client'
]