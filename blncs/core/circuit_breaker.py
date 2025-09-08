"""
Circuit Breaker pattern implementation for BLNCS
Prevents cascading failures and improves system resilience.
"""

import time
import threading
from typing import Callable, Any, Optional, Dict
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import wraps

from .logger import get_logger
from .exceptions import CircuitBreakerError


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"      # Blocking calls due to failures
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker"""
    failure_threshold: int = 5  # Failures before opening
    success_threshold: int = 2  # Successes in half-open before closing
    timeout: float = 60.0  # Seconds before trying half-open
    expected_exception: tuple = (Exception,)  # Exceptions to track
    name: str = "default"  # Circuit breaker name


@dataclass
class CircuitBreakerStats:
    """Statistics for circuit breaker"""
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    last_failure_time: Optional[datetime] = None
    state_changes: list = field(default_factory=list)
    
    def reset(self):
        """Reset statistics"""
        self.consecutive_failures = 0
        self.consecutive_successes = 0
    
    def record_success(self):
        """Record successful call"""
        self.total_calls += 1
        self.successful_calls += 1
        self.consecutive_successes += 1
        self.consecutive_failures = 0
    
    def record_failure(self):
        """Record failed call"""
        self.total_calls += 1
        self.failed_calls += 1
        self.consecutive_failures += 1
        self.consecutive_successes = 0
        self.last_failure_time = datetime.now()


class CircuitBreaker:
    """Circuit breaker implementation"""
    
    def __init__(self, config: Optional[CircuitBreakerConfig] = None):
        self.config = config or CircuitBreakerConfig()
        self.logger = get_logger(__name__)
        self.state = CircuitState.CLOSED
        self.stats = CircuitBreakerStats()
        self._lock = threading.RLock()
        self._state_change_time = datetime.now()
    
    def __call__(self, func: Callable) -> Callable:
        """Decorator for protecting functions with circuit breaker"""
        @wraps(func)
        def wrapper(*args, **kwargs):
            return self.call(func, *args, **kwargs)
        
        # Add introspection methods
        wrapper.get_state = lambda: self.state
        wrapper.get_stats = lambda: self.stats
        wrapper.reset = self.reset
        
        return wrapper
    
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection"""
        with self._lock:
            # Check if we should allow the call
            if self.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self._transition_to_half_open()
                else:
                    raise CircuitBreakerError(
                        f"Circuit breaker is OPEN for {self.config.name}",
                        failure_count=self.stats.consecutive_failures
                    )
        
        # Attempt the call
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except self.config.expected_exception as e:
            self._on_failure()
            raise
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to try half-open state"""
        if not self.stats.last_failure_time:
            return True
        
        time_since_failure = (datetime.now() - self._state_change_time).total_seconds()
        return time_since_failure >= self.config.timeout
    
    def _on_success(self):
        """Handle successful call"""
        with self._lock:
            self.stats.record_success()
            
            if self.state == CircuitState.HALF_OPEN:
                if self.stats.consecutive_successes >= self.config.success_threshold:
                    self._transition_to_closed()
            elif self.state == CircuitState.OPEN:
                # This shouldn't happen, but handle it
                self._transition_to_half_open()
    
    def _on_failure(self):
        """Handle failed call"""
        with self._lock:
            self.stats.record_failure()
            
            if self.state == CircuitState.CLOSED:
                if self.stats.consecutive_failures >= self.config.failure_threshold:
                    self._transition_to_open()
            elif self.state == CircuitState.HALF_OPEN:
                self._transition_to_open()
    
    def _transition_to_open(self):
        """Transition to OPEN state"""
        self.state = CircuitState.OPEN
        self._state_change_time = datetime.now()
        self.stats.state_changes.append({
            'from': self.state,
            'to': CircuitState.OPEN,
            'time': self._state_change_time,
            'reason': f'Failures exceeded threshold ({self.stats.consecutive_failures})'
        })
        self.logger.warning(f"Circuit breaker {self.config.name} is now OPEN")
    
    def _transition_to_closed(self):
        """Transition to CLOSED state"""
        previous_state = self.state
        self.state = CircuitState.CLOSED
        self._state_change_time = datetime.now()
        self.stats.reset()
        self.stats.state_changes.append({
            'from': previous_state,
            'to': CircuitState.CLOSED,
            'time': self._state_change_time,
            'reason': 'Service recovered'
        })
        self.logger.info(f"Circuit breaker {self.config.name} is now CLOSED")
    
    def _transition_to_half_open(self):
        """Transition to HALF_OPEN state"""
        self.state = CircuitState.HALF_OPEN
        self._state_change_time = datetime.now()
        self.stats.reset()
        self.stats.state_changes.append({
            'from': CircuitState.OPEN,
            'to': CircuitState.HALF_OPEN,
            'time': self._state_change_time,
            'reason': 'Testing service recovery'
        })
        self.logger.info(f"Circuit breaker {self.config.name} is now HALF_OPEN")
    
    def reset(self):
        """Manually reset the circuit breaker"""
        with self._lock:
            self.state = CircuitState.CLOSED
            self.stats.reset()
            self._state_change_time = datetime.now()
            self.logger.info(f"Circuit breaker {self.config.name} manually reset")
    
    def get_status(self) -> Dict[str, Any]:
        """Get circuit breaker status"""
        with self._lock:
            success_rate = (
                self.stats.successful_calls / self.stats.total_calls
                if self.stats.total_calls > 0 else 0
            )
            
            return {
                'name': self.config.name,
                'state': self.state.value,
                'total_calls': self.stats.total_calls,
                'successful_calls': self.stats.successful_calls,
                'failed_calls': self.stats.failed_calls,
                'success_rate': success_rate,
                'consecutive_failures': self.stats.consecutive_failures,
                'consecutive_successes': self.stats.consecutive_successes,
                'last_failure': self.stats.last_failure_time.isoformat() if self.stats.last_failure_time else None,
                'state_change_time': self._state_change_time.isoformat()
            }


# Global circuit breakers registry
_circuit_breakers: Dict[str, CircuitBreaker] = {}


def get_circuit_breaker(name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
    """Get or create a circuit breaker by name"""
    global _circuit_breakers
    
    if name not in _circuit_breakers:
        if config is None:
            config = CircuitBreakerConfig(name=name)
        _circuit_breakers[name] = CircuitBreaker(config)
    
    return _circuit_breakers[name]


def circuit_breaker(name: str = "default",
                   failure_threshold: int = 5,
                   success_threshold: int = 2,
                   timeout: float = 60.0,
                   expected_exception: tuple = (Exception,)) -> Callable:
    """Decorator factory for circuit breaker protection"""
    config = CircuitBreakerConfig(
        name=name,
        failure_threshold=failure_threshold,
        success_threshold=success_threshold,
        timeout=timeout,
        expected_exception=expected_exception
    )
    
    breaker = get_circuit_breaker(name, config)
    return breaker


def get_all_circuit_breakers_status() -> Dict[str, Any]:
    """Get status of all circuit breakers"""
    global _circuit_breakers
    return {
        name: breaker.get_status()
        for name, breaker in _circuit_breakers.items()
    }


def reset_all_circuit_breakers():
    """Reset all circuit breakers"""
    global _circuit_breakers
    for breaker in _circuit_breakers.values():
        breaker.reset()