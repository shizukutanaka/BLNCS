"""
Resilience Patterns - Circuit Breaker, Retry, Timeout, Bulkhead
Implements enterprise-grade resilience patterns for fault tolerance.
"""

import asyncio
import time
import functools
import logging
from typing import Any, Callable, Dict, List, Optional, Union, TypeVar, Generic
from datetime import datetime, timezone, timedelta
from enum import Enum
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
import random
import statistics
from concurrent.futures import ThreadPoolExecutor
import threading

from ..core.structured_logging import StructuredLogger


T = TypeVar('T')
F = TypeVar('F', bound=Callable[..., Any])


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"        # Normal operation
    OPEN = "open"           # Circuit is open, failing fast
    HALF_OPEN = "half_open" # Testing if service has recovered


class FailureType(Enum):
    """Types of failures that can trigger circuit breaker."""
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"
    SERVICE_ERROR = "service_error"
    RATE_LIMIT = "rate_limit"
    AUTHENTICATION_ERROR = "authentication_error"


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""
    failure_threshold: int = 5          # Failures before opening
    recovery_timeout: int = 60          # Seconds before trying half-open
    success_threshold: int = 3          # Successes to close from half-open
    timeout_duration: float = 30.0     # Request timeout in seconds
    monitored_exceptions: tuple = (Exception,)
    excluded_exceptions: tuple = ()


@dataclass
class CallResult:
    """Result of a circuit breaker call."""
    success: bool
    duration: float
    error: Optional[Exception] = None
    failure_type: Optional[FailureType] = None


class CircuitBreakerMetrics:
    """Metrics collection for circuit breaker."""
    
    def __init__(self):
        self.total_calls = 0
        self.successful_calls = 0
        self.failed_calls = 0
        self.circuit_open_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.recent_failures: List[datetime] = []
        self.response_times: List[float] = []
        self._lock = threading.Lock()
    
    def record_success(self, duration: float):
        """Record successful call."""
        with self._lock:
            self.total_calls += 1
            self.successful_calls += 1
            self.response_times.append(duration)
            self._cleanup_old_data()
    
    def record_failure(self, failure_type: FailureType):
        """Record failed call."""
        with self._lock:
            self.total_calls += 1
            self.failed_calls += 1
            now = datetime.now(timezone.utc)
            self.last_failure_time = now
            self.recent_failures.append(now)
            self._cleanup_old_data()
    
    def record_circuit_open(self):
        """Record circuit opening."""
        with self._lock:
            self.circuit_open_count += 1
    
    def _cleanup_old_data(self):
        """Clean up old metrics data."""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=10)
        
        # Keep only recent failures
        self.recent_failures = [f for f in self.recent_failures if f > cutoff]
        
        # Keep only recent response times (last 100)
        if len(self.response_times) > 100:
            self.response_times = self.response_times[-100:]
    
    def get_failure_rate(self, window_minutes: int = 5) -> float:
        """Get failure rate in the specified window."""
        with self._lock:
            if self.total_calls == 0:
                return 0.0
            
            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(minutes=window_minutes)
            recent_failure_count = len([f for f in self.recent_failures if f > cutoff])
            
            # Approximate total calls in window
            window_calls = max(1, self.total_calls // max(1, (10 // window_minutes)))
            return recent_failure_count / window_calls
    
    def get_average_response_time(self) -> float:
        """Get average response time."""
        with self._lock:
            return statistics.mean(self.response_times) if self.response_times else 0.0


class CircuitBreaker:
    """Circuit breaker implementation with advanced features."""
    
    def __init__(self, name: str, config: CircuitBreakerConfig):
        self.name = name
        self.config = config
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: Optional[float] = None
        self.next_attempt_time: Optional[float] = None
        self.metrics = CircuitBreakerMetrics()
        self.logger = StructuredLogger(f"circuit_breaker.{name}")
        self._lock = asyncio.Lock()
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection."""
        async with self._lock:
            # Check if circuit should remain open
            if self._should_attempt_call():
                try:
                    result = await self._execute_call(func, *args, **kwargs)
                    await self._on_success()
                    return result
                except Exception as e:
                    await self._on_failure(e)
                    raise
            else:
                # Circuit is open, fail fast
                self.metrics.record_circuit_open()
                self.logger.warning(
                    "Circuit breaker is open, failing fast",
                    extra={"state": self.state.value, "failure_count": self.failure_count}
                )
                raise CircuitBreakerOpenError(f"Circuit breaker '{self.name}' is open")
    
    def _should_attempt_call(self) -> bool:
        """Determine if call should be attempted based on circuit state."""
        now = time.time()
        
        if self.state == CircuitState.CLOSED:
            return True
        elif self.state == CircuitState.OPEN:
            if self.next_attempt_time and now >= self.next_attempt_time:
                self.state = CircuitState.HALF_OPEN
                self.success_count = 0
                self.logger.info(
                    "Circuit breaker transitioning to half-open",
                    extra={"recovery_timeout": self.config.recovery_timeout}
                )
                return True
            return False
        elif self.state == CircuitState.HALF_OPEN:
            return True
        
        return False
    
    async def _execute_call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute the actual function call with timeout."""
        start_time = time.time()
        
        try:
            if asyncio.iscoroutinefunction(func):
                result = await asyncio.wait_for(
                    func(*args, **kwargs),
                    timeout=self.config.timeout_duration
                )
            else:
                # Run sync function in thread pool
                loop = asyncio.get_event_loop()
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, func, *args, **kwargs),
                    timeout=self.config.timeout_duration
                )
            
            duration = time.time() - start_time
            self.metrics.record_success(duration)
            return result
            
        except asyncio.TimeoutError:
            duration = time.time() - start_time
            self.logger.warning(
                "Function call timed out",
                extra={"timeout": self.config.timeout_duration, "duration": duration}
            )
            raise CircuitBreakerError("Call timed out")
    
    async def _on_success(self):
        """Handle successful call."""
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                self.logger.info(
                    "Circuit breaker closed after successful recovery",
                    extra={"success_count": self.success_count}
                )
        elif self.state == CircuitState.CLOSED:
            # Reset failure count on success
            self.failure_count = max(0, self.failure_count - 1)
    
    async def _on_failure(self, exception: Exception):
        """Handle failed call."""
        # Check if exception should be monitored
        if not self._should_count_failure(exception):
            return
        
        failure_type = self._classify_failure(exception)
        self.metrics.record_failure(failure_type)
        
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        self.logger.warning(
            "Circuit breaker recorded failure",
            extra={
                "failure_count": self.failure_count,
                "failure_type": failure_type.value,
                "exception": str(exception)
            }
        )
        
        if self.state == CircuitState.HALF_OPEN:
            # Immediately open on failure in half-open state
            self._open_circuit()
        elif self.failure_count >= self.config.failure_threshold:
            self._open_circuit()
    
    def _should_count_failure(self, exception: Exception) -> bool:
        """Determine if exception should count towards circuit breaker."""
        # Don't count excluded exceptions
        if isinstance(exception, self.config.excluded_exceptions):
            return False
        
        # Only count monitored exceptions
        return isinstance(exception, self.config.monitored_exceptions)
    
    def _classify_failure(self, exception: Exception) -> FailureType:
        """Classify the type of failure."""
        exception_name = type(exception).__name__.lower()
        
        if 'timeout' in exception_name:
            return FailureType.TIMEOUT
        elif 'connection' in exception_name:
            return FailureType.CONNECTION_ERROR
        elif 'auth' in exception_name:
            return FailureType.AUTHENTICATION_ERROR
        elif 'rate' in exception_name or 'limit' in exception_name:
            return FailureType.RATE_LIMIT
        else:
            return FailureType.SERVICE_ERROR
    
    def _open_circuit(self):
        """Open the circuit."""
        self.state = CircuitState.OPEN
        self.next_attempt_time = time.time() + self.config.recovery_timeout
        
        self.logger.error(
            "Circuit breaker opened",
            extra={
                "failure_count": self.failure_count,
                "recovery_timeout": self.config.recovery_timeout
            }
        )
    
    def get_state(self) -> Dict[str, Any]:
        """Get current circuit breaker state."""
        return {
            'name': self.name,
            'state': self.state.value,
            'failure_count': self.failure_count,
            'success_count': self.success_count,
            'failure_threshold': self.config.failure_threshold,
            'recovery_timeout': self.config.recovery_timeout,
            'metrics': {
                'total_calls': self.metrics.total_calls,
                'successful_calls': self.metrics.successful_calls,
                'failed_calls': self.metrics.failed_calls,
                'failure_rate_5min': self.metrics.get_failure_rate(5),
                'avg_response_time': self.metrics.get_average_response_time()
            }
        }


class RetryConfig:
    """Configuration for retry mechanism."""
    
    def __init__(self, max_attempts: int = 3, base_delay: float = 1.0,
                 max_delay: float = 60.0, exponential_base: float = 2.0,
                 jitter: bool = True):
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter


class RetryStrategy(ABC):
    """Abstract retry strategy."""
    
    @abstractmethod
    def get_delay(self, attempt: int) -> float:
        """Get delay before next retry attempt."""
        pass


class ExponentialBackoffStrategy(RetryStrategy):
    """Exponential backoff retry strategy."""
    
    def __init__(self, config: RetryConfig):
        self.config = config
    
    def get_delay(self, attempt: int) -> float:
        """Calculate exponential backoff delay."""
        delay = self.config.base_delay * (self.config.exponential_base ** (attempt - 1))
        delay = min(delay, self.config.max_delay)
        
        if self.config.jitter:
            # Add jitter to prevent thundering herd
            jitter = random.uniform(0.1, 0.3) * delay
            delay += jitter
        
        return delay


class LinearBackoffStrategy(RetryStrategy):
    """Linear backoff retry strategy."""
    
    def __init__(self, config: RetryConfig):
        self.config = config
    
    def get_delay(self, attempt: int) -> float:
        """Calculate linear backoff delay."""
        delay = self.config.base_delay * attempt
        delay = min(delay, self.config.max_delay)
        
        if self.config.jitter:
            jitter = random.uniform(0.1, 0.3) * delay
            delay += jitter
        
        return delay


class RetryMechanism:
    """Retry mechanism with configurable strategies."""
    
    def __init__(self, name: str, config: RetryConfig, 
                 strategy: Optional[RetryStrategy] = None):
        self.name = name
        self.config = config
        self.strategy = strategy or ExponentialBackoffStrategy(config)
        self.logger = StructuredLogger(f"retry.{name}")
    
    async def execute(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with retry logic."""
        last_exception = None
        
        for attempt in range(1, self.config.max_attempts + 1):
            try:
                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)
                    
            except Exception as e:
                last_exception = e
                
                if attempt == self.config.max_attempts:
                    self.logger.error(
                        "All retry attempts failed",
                        extra={"attempts": attempt, "exception": str(e)}
                    )
                    break
                
                delay = self.strategy.get_delay(attempt)
                
                self.logger.warning(
                    "Retry attempt failed, waiting before next attempt",
                    extra={
                        "attempt": attempt,
                        "max_attempts": self.config.max_attempts,
                        "delay": delay,
                        "exception": str(e)
                    }
                )
                
                await asyncio.sleep(delay)
        
        raise last_exception


@dataclass
class BulkheadConfig:
    """Configuration for bulkhead pattern."""
    max_concurrent_calls: int = 10
    queue_size: int = 100
    timeout: float = 30.0


class Bulkhead:
    """Bulkhead pattern implementation for resource isolation."""
    
    def __init__(self, name: str, config: BulkheadConfig):
        self.name = name
        self.config = config
        self.semaphore = asyncio.Semaphore(config.max_concurrent_calls)
        self.queue = asyncio.Queue(maxsize=config.queue_size)
        self.active_calls = 0
        self.rejected_calls = 0
        self.logger = StructuredLogger(f"bulkhead.{name}")
        self._lock = asyncio.Lock()
    
    async def execute(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with bulkhead protection."""
        try:
            async with asyncio.timeout(self.config.timeout):
                async with self.semaphore:
                    async with self._lock:
                        self.active_calls += 1
                    
                    try:
                        if asyncio.iscoroutinefunction(func):
                            return await func(*args, **kwargs)
                        else:
                            loop = asyncio.get_event_loop()
                            return await loop.run_in_executor(None, func, *args, **kwargs)
                    finally:
                        async with self._lock:
                            self.active_calls -= 1
                            
        except asyncio.TimeoutError:
            async with self._lock:
                self.rejected_calls += 1
            self.logger.warning(
                "Bulkhead call timed out",
                extra={"timeout": self.config.timeout}
            )
            raise BulkheadTimeoutError(f"Bulkhead '{self.name}' call timed out")
        
        except Exception as e:
            async with self._lock:
                self.rejected_calls += 1
            raise
    
    def get_stats(self) -> Dict[str, Any]:
        """Get bulkhead statistics."""
        return {
            'name': self.name,
            'active_calls': self.active_calls,
            'rejected_calls': self.rejected_calls,
            'max_concurrent_calls': self.config.max_concurrent_calls,
            'available_permits': self.semaphore._value
        }


class ResilienceManager:
    """Manager for all resilience patterns."""
    
    def __init__(self):
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.retry_mechanisms: Dict[str, RetryMechanism] = {}
        self.bulkheads: Dict[str, Bulkhead] = {}
        self.logger = StructuredLogger("resilience_manager")
    
    def register_circuit_breaker(self, name: str, config: CircuitBreakerConfig) -> CircuitBreaker:
        """Register a circuit breaker."""
        circuit_breaker = CircuitBreaker(name, config)
        self.circuit_breakers[name] = circuit_breaker
        self.logger.info(f"Registered circuit breaker: {name}")
        return circuit_breaker
    
    def register_retry_mechanism(self, name: str, config: RetryConfig, 
                                strategy: Optional[RetryStrategy] = None) -> RetryMechanism:
        """Register a retry mechanism."""
        retry_mechanism = RetryMechanism(name, config, strategy)
        self.retry_mechanisms[name] = retry_mechanism
        self.logger.info(f"Registered retry mechanism: {name}")
        return retry_mechanism
    
    def register_bulkhead(self, name: str, config: BulkheadConfig) -> Bulkhead:
        """Register a bulkhead."""
        bulkhead = Bulkhead(name, config)
        self.bulkheads[name] = bulkhead
        self.logger.info(f"Registered bulkhead: {name}")
        return bulkhead
    
    def get_circuit_breaker(self, name: str) -> Optional[CircuitBreaker]:
        """Get circuit breaker by name."""
        return self.circuit_breakers.get(name)
    
    def get_retry_mechanism(self, name: str) -> Optional[RetryMechanism]:
        """Get retry mechanism by name."""
        return self.retry_mechanisms.get(name)
    
    def get_bulkhead(self, name: str) -> Optional[Bulkhead]:
        """Get bulkhead by name."""
        return self.bulkheads.get(name)
    
    def get_status(self) -> Dict[str, Any]:
        """Get status of all resilience components."""
        return {
            'circuit_breakers': {name: cb.get_state() for name, cb in self.circuit_breakers.items()},
            'bulkheads': {name: b.get_stats() for name, b in self.bulkheads.items()},
            'retry_mechanisms': list(self.retry_mechanisms.keys())
        }


# Decorator functions for easy use
def circuit_breaker(name: str, **kwargs):
    """Decorator for circuit breaker protection."""
    def decorator(func: F) -> F:
        config = CircuitBreakerConfig(**kwargs)
        cb = CircuitBreaker(name, config)
        
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            return await cb.call(func, *args, **kwargs)
        
        return wrapper
    return decorator


def retry(name: str, **kwargs):
    """Decorator for retry protection."""
    def decorator(func: F) -> F:
        config = RetryConfig(**kwargs)
        retry_mechanism = RetryMechanism(name, config)
        
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            return await retry_mechanism.execute(func, *args, **kwargs)
        
        return wrapper
    return decorator


def bulkhead(name: str, **kwargs):
    """Decorator for bulkhead protection."""
    def decorator(func: F) -> F:
        config = BulkheadConfig(**kwargs)
        bulkhead_instance = Bulkhead(name, config)
        
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            return await bulkhead_instance.execute(func, *args, **kwargs)
        
        return wrapper
    return decorator


# Combined decorator for full resilience
def resilient(circuit_breaker_name: str = None, retry_name: str = None, 
              bulkhead_name: str = None, **kwargs):
    """Decorator combining circuit breaker, retry, and bulkhead."""
    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Apply patterns in order: bulkhead -> circuit breaker -> retry -> function
            call_func = func
            
            if retry_name:
                retry_config = RetryConfig(**kwargs.get('retry', {}))
                retry_mechanism = RetryMechanism(retry_name, retry_config)
                original_func = call_func
                call_func = lambda *a, **kw: retry_mechanism.execute(original_func, *a, **kw)
            
            if circuit_breaker_name:
                cb_config = CircuitBreakerConfig(**kwargs.get('circuit_breaker', {}))
                cb = CircuitBreaker(circuit_breaker_name, cb_config)
                original_func = call_func
                call_func = lambda *a, **kw: cb.call(original_func, *a, **kw)
            
            if bulkhead_name:
                bh_config = BulkheadConfig(**kwargs.get('bulkhead', {}))
                bh = Bulkhead(bulkhead_name, bh_config)
                original_func = call_func
                call_func = lambda *a, **kw: bh.execute(original_func, *a, **kw)
            
            return await call_func(*args, **kwargs)
        
        return wrapper
    return decorator


# Custom Exceptions
class ResilienceError(Exception):
    """Base exception for resilience patterns."""
    pass


class CircuitBreakerError(ResilienceError):
    """Circuit breaker related errors."""
    pass


class CircuitBreakerOpenError(CircuitBreakerError):
    """Circuit breaker is open."""
    pass


class BulkheadTimeoutError(ResilienceError):
    """Bulkhead timeout error."""
    pass


# Global resilience manager instance
_resilience_manager: Optional[ResilienceManager] = None


def get_resilience_manager() -> ResilienceManager:
    """Get global resilience manager instance."""
    global _resilience_manager
    if _resilience_manager is None:
        _resilience_manager = ResilienceManager()
    return _resilience_manager