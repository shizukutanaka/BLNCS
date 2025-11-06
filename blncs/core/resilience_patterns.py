#!/usr/bin/env python3
"""
Resilience Patterns - Circuit Breaker and Bulkhead
Implements patterns for fault tolerance and resilience
Based on 2025 microservices best practices
"""

import asyncio
import logging
import time
from typing import Callable, Awaitable, Optional, TypeVar, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import deque

logger = logging.getLogger(__name__)

T = TypeVar('T')


class CircuitState(Enum):
    """Circuit breaker state"""
    CLOSED = "closed"          # Normal operation
    OPEN = "open"             # Failing, reject requests
    HALF_OPEN = "half_open"   # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker"""
    failure_threshold: int = 5        # Consecutive failures to open circuit
    success_threshold: int = 2        # Consecutive successes to close circuit
    timeout_seconds: int = 60         # Time to wait before half-open
    max_request_size: int = 100       # Max requests to track


class CircuitBreaker:
    """
    Circuit Breaker Pattern
    Prevents cascading failures by monitoring request success/failure rates
    States: CLOSED (normal) -> OPEN (failing) -> HALF_OPEN (testing) -> CLOSED
    """

    def __init__(self, config: Optional[CircuitBreakerConfig] = None):
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.last_state_change = datetime.utcnow()
        self.request_history = deque(maxlen=self.config.max_request_size)

    @property
    def is_open(self) -> bool:
        """Check if circuit is open"""
        if self.state == CircuitState.OPEN:
            # Check if timeout has elapsed
            elapsed = (datetime.utcnow() - self.last_state_change).total_seconds()
            if elapsed >= self.config.timeout_seconds:
                self._transition_to_half_open()
                return False
            return True
        return False

    def _transition_to_half_open(self) -> None:
        """Transition from OPEN to HALF_OPEN"""
        self.state = CircuitState.HALF_OPEN
        self.success_count = 0
        self.failure_count = 0
        self.last_state_change = datetime.utcnow()
        logger.info("Circuit breaker transitioned to HALF_OPEN")

    def _transition_to_closed(self) -> None:
        """Transition to CLOSED state"""
        self.state = CircuitState.CLOSED
        self.success_count = 0
        self.failure_count = 0
        self.last_state_change = datetime.utcnow()
        logger.info("Circuit breaker transitioned to CLOSED")

    def _transition_to_open(self) -> None:
        """Transition to OPEN state"""
        self.state = CircuitState.OPEN
        self.last_state_change = datetime.utcnow()
        logger.warning("Circuit breaker transitioned to OPEN")

    async def call(self, func: Callable[..., Awaitable[T]], *args, **kwargs) -> T:
        """
        Execute function with circuit breaker protection

        Args:
            func: Async function to execute
            *args, **kwargs: Arguments for function

        Raises:
            RuntimeError: If circuit is open
        """
        if self.is_open:
            raise RuntimeError("Circuit breaker is OPEN - rejecting requests")

        try:
            result = await func(*args, **kwargs)
            self._record_success()
            return result

        except Exception as e:
            self._record_failure()
            raise

    def _record_success(self) -> None:
        """Record successful request"""
        self.request_history.append({'status': 'success', 'time': datetime.utcnow()})
        self.failure_count = 0
        self.success_count += 1

        logger.debug(f"Circuit breaker recorded success (total: {self.success_count})")

        # If in HALF_OPEN, check if we can close
        if self.state == CircuitState.HALF_OPEN:
            if self.success_count >= self.config.success_threshold:
                self._transition_to_closed()

    def _record_failure(self) -> None:
        """Record failed request"""
        self.request_history.append({'status': 'failure', 'time': datetime.utcnow()})
        self.last_failure_time = datetime.utcnow()
        self.success_count = 0
        self.failure_count += 1

        logger.debug(f"Circuit breaker recorded failure (total: {self.failure_count})")

        # Check if we should open circuit
        if self.failure_count >= self.config.failure_threshold:
            self._transition_to_open()

    def get_state(self) -> str:
        """Get current circuit state"""
        return self.state.value

    def get_metrics(self) -> dict:
        """Get circuit breaker metrics"""
        return {
            'state': self.state.value,
            'failure_count': self.failure_count,
            'success_count': self.success_count,
            'last_failure': self.last_failure_time.isoformat() if self.last_failure_time else None,
            'requests_tracked': len(self.request_history)
        }


@dataclass
class BulkheadConfig:
    """Configuration for bulkhead pattern"""
    max_concurrent_calls: int = 10      # Max concurrent requests
    max_wait_duration_ms: int = 1000    # Max wait time for semaphore
    max_queue_size: int = 100           # Max queued requests


class Bulkhead:
    """
    Bulkhead Pattern (Isolation Pattern)
    Limits concurrent resource access to prevent resource exhaustion
    Inspired by ship compartments - failure in one doesn't affect others
    """

    def __init__(self, config: Optional[BulkheadConfig] = None):
        self.config = config or BulkheadConfig()
        self.semaphore = asyncio.Semaphore(self.config.max_concurrent_calls)
        self.queue_size = 0
        self.rejected_count = 0
        self.active_count = 0
        self.max_active_count = 0

    async def call(
        self,
        func: Callable[..., Awaitable[T]],
        *args,
        **kwargs
    ) -> T:
        """
        Execute function with bulkhead protection

        Args:
            func: Async function to execute
            *args, **kwargs: Arguments for function

        Returns:
            Result from function

        Raises:
            RuntimeError: If queue is full
        """
        # Check if queue is full
        if self.queue_size >= self.config.max_queue_size:
            self.rejected_count += 1
            raise RuntimeError(
                f"Bulkhead queue full ({self.queue_size}/{self.config.max_queue_size})"
            )

        self.queue_size += 1

        try:
            # Acquire semaphore with timeout
            acquired = await asyncio.wait_for(
                self.semaphore.acquire(),
                timeout=self.config.max_wait_duration_ms / 1000.0
            )

            if acquired:
                self.active_count += 1
                self.max_active_count = max(self.max_active_count, self.active_count)

                try:
                    result = await func(*args, **kwargs)
                    return result
                finally:
                    self.active_count -= 1

        except asyncio.TimeoutError:
            self.rejected_count += 1
            raise RuntimeError("Bulkhead wait timeout exceeded")

        finally:
            self.queue_size -= 1

    def get_metrics(self) -> dict:
        """Get bulkhead metrics"""
        return {
            'active_calls': self.active_count,
            'queued_calls': self.queue_size,
            'max_active_calls': self.max_active_count,
            'rejected_calls': self.rejected_count,
            'max_concurrent': self.config.max_concurrent_calls
        }


class ResilientOperation:
    """
    Combines Circuit Breaker and Bulkhead patterns
    Provides comprehensive resilience
    """

    def __init__(
        self,
        circuit_breaker_config: Optional[CircuitBreakerConfig] = None,
        bulkhead_config: Optional[BulkheadConfig] = None
    ):
        self.circuit_breaker = CircuitBreaker(circuit_breaker_config)
        self.bulkhead = Bulkhead(bulkhead_config)

    async def execute(
        self,
        func: Callable[..., Awaitable[T]],
        *args,
        **kwargs
    ) -> T:
        """
        Execute function with both circuit breaker and bulkhead protection

        Args:
            func: Async function to execute
            *args, **kwargs: Arguments for function

        Returns:
            Result from function
        """
        # Check circuit breaker first
        if self.circuit_breaker.is_open:
            raise RuntimeError("Circuit breaker is open")

        # Then apply bulkhead
        async def protected_call():
            return await self.circuit_breaker.call(func, *args, **kwargs)

        return await self.bulkhead.call(protected_call)

    def get_health(self) -> dict:
        """Get health status of resilient operation"""
        return {
            'circuit_breaker': self.circuit_breaker.get_metrics(),
            'bulkhead': self.bulkhead.get_metrics(),
            'healthy': (
                not self.circuit_breaker.is_open and
                self.bulkhead.active_count < self.bulkhead.config.max_concurrent_calls
            )
        }


class Retry:
    """
    Retry Pattern
    Automatically retries failed operations with exponential backoff
    """

    def __init__(
        self,
        max_attempts: int = 3,
        initial_delay_ms: float = 100,
        max_delay_ms: float = 10000,
        backoff_factor: float = 2.0,
        jitter: bool = True
    ):
        self.max_attempts = max_attempts
        self.initial_delay_ms = initial_delay_ms
        self.max_delay_ms = max_delay_ms
        self.backoff_factor = backoff_factor
        self.jitter = jitter
        self.attempt_count = 0

    async def execute(
        self,
        func: Callable[..., Awaitable[T]],
        *args,
        **kwargs
    ) -> T:
        """
        Execute function with retry logic

        Args:
            func: Async function to execute
            *args, **kwargs: Arguments for function

        Returns:
            Result from function

        Raises:
            Exception: Last exception if all retries fail
        """
        self.attempt_count = 0
        last_exception = None

        for attempt in range(self.max_attempts):
            self.attempt_count = attempt + 1

            try:
                result = await func(*args, **kwargs)
                logger.debug(f"Retry succeeded on attempt {self.attempt_count}")
                return result

            except Exception as e:
                last_exception = e
                logger.warning(f"Attempt {self.attempt_count} failed: {e}")

                if attempt < self.max_attempts - 1:
                    delay = self._calculate_delay(attempt)
                    logger.debug(f"Retrying after {delay}ms")
                    await asyncio.sleep(delay / 1000.0)

        logger.error(
            f"All {self.max_attempts} retry attempts failed: {last_exception}"
        )
        raise last_exception

    def _calculate_delay(self, attempt: int) -> float:
        """Calculate delay with exponential backoff"""
        delay = self.initial_delay_ms * (self.backoff_factor ** attempt)
        delay = min(delay, self.max_delay_ms)

        if self.jitter:
            import random
            delay = delay * (0.5 + random.random())

        return delay


__all__ = [
    'CircuitState',
    'CircuitBreakerConfig',
    'CircuitBreaker',
    'BulkheadConfig',
    'Bulkhead',
    'ResilientOperation',
    'Retry',
]
