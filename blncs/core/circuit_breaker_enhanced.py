"""
Enhanced Circuit Breaker Implementation for BLNCS
Provides resilience patterns with advanced monitoring and recovery.
"""

import time
import threading
import asyncio
from typing import Dict, Any, Optional, Callable, Union, List
from dataclasses import dataclass, field
from enum import Enum
from contextlib import contextmanager, asynccontextmanager

from .logger import get_logger
from .exceptions import CircuitBreakerError, BLNCSError


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"         # Circuit is open, requests fail fast
    HALF_OPEN = "half_open"  # Testing if service has recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker"""
    failure_threshold: int = 5           # Number of failures to open circuit
    recovery_timeout: int = 60           # Seconds to wait before attempting recovery
    success_threshold: int = 2           # Successes needed to close circuit from half-open
    monitor_window: int = 300           # Monitoring window in seconds
    slow_call_threshold: float = 5.0    # Slow call threshold in seconds
    slow_call_rate_threshold: float = 0.5  # Rate of slow calls to trip circuit


@dataclass
class CircuitMetrics:
    """Metrics for circuit breaker monitoring"""
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    slow_calls: int = 0
    last_failure_time: Optional[float] = None
    last_success_time: Optional[float] = None
    state_change_time: float = field(default_factory=time.time)


class EnhancedCircuitBreaker:
    """Enhanced circuit breaker with comprehensive monitoring"""
    
    def __init__(self, name: str, config: Optional[CircuitBreakerConfig] = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.logger = get_logger(f"{__name__}.{name}")
        
        self._state = CircuitState.CLOSED
        self._metrics = CircuitMetrics()
        self._lock = threading.RLock()
        self._half_open_success_count = 0
        
        # Sliding window for call tracking
        self._call_history: List[Dict[str, Any]] = []
        
    @property
    def state(self) -> CircuitState:
        """Get current circuit state"""
        return self._state
    
    @property
    def metrics(self) -> CircuitMetrics:
        """Get current metrics (copy)"""
        with self._lock:
            return CircuitMetrics(
                total_calls=self._metrics.total_calls,
                successful_calls=self._metrics.successful_calls,
                failed_calls=self._metrics.failed_calls,
                slow_calls=self._metrics.slow_calls,
                last_failure_time=self._metrics.last_failure_time,
                last_success_time=self._metrics.last_success_time,
                state_change_time=self._metrics.state_change_time
            )
    
    def _should_attempt_reset(self) -> bool:
        """Check if we should attempt to reset from OPEN to HALF_OPEN"""
        if self._state != CircuitState.OPEN:
            return False
        
        if self._metrics.last_failure_time is None:
            return True
        
        return (time.time() - self._metrics.last_failure_time) >= self.config.recovery_timeout
    
    def _should_trip_circuit(self) -> bool:
        """Check if circuit should trip based on current metrics"""
        if self._metrics.total_calls < self.config.failure_threshold:
            return False
        
        # Clean old entries from sliding window
        current_time = time.time()
        self._call_history = [
            call for call in self._call_history
            if current_time - call['timestamp'] <= self.config.monitor_window
        ]
        
        if len(self._call_history) < self.config.failure_threshold:
            return False
        
        # Check failure rate
        recent_failures = sum(1 for call in self._call_history if not call['success'])
        failure_rate = recent_failures / len(self._call_history)
        
        # Check slow call rate
        recent_slow_calls = sum(1 for call in self._call_history if call.get('slow', False))
        slow_call_rate = recent_slow_calls / len(self._call_history) if self._call_history else 0
        
        return (failure_rate >= 0.5 or  # 50% failure rate
                slow_call_rate >= self.config.slow_call_rate_threshold)
    
    def _record_call(self, success: bool, duration: float) -> None:
        """Record call statistics"""
        current_time = time.time()
        is_slow = duration >= self.config.slow_call_threshold
        
        with self._lock:
            self._metrics.total_calls += 1
            
            if success:
                self._metrics.successful_calls += 1
                self._metrics.last_success_time = current_time
            else:
                self._metrics.failed_calls += 1
                self._metrics.last_failure_time = current_time
            
            if is_slow:
                self._metrics.slow_calls += 1
            
            # Add to sliding window
            self._call_history.append({
                'timestamp': current_time,
                'success': success,
                'duration': duration,
                'slow': is_slow
            })
            
            # Limit history size
            if len(self._call_history) > 1000:
                self._call_history = self._call_history[-500:]
    
    def _change_state(self, new_state: CircuitState, reason: str = "") -> None:
        """Change circuit state with logging"""
        if self._state == new_state:
            return
        
        old_state = self._state
        self._state = new_state
        self._metrics.state_change_time = time.time()
        
        if new_state == CircuitState.HALF_OPEN:
            self._half_open_success_count = 0
        
        self.logger.info(f"Circuit breaker state changed: {old_state.value} -> {new_state.value}. Reason: {reason}")
    
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function through circuit breaker"""
        # Check if circuit should attempt reset
        if self._state == CircuitState.OPEN and self._should_attempt_reset():
            with self._lock:
                if self._state == CircuitState.OPEN:  # Double-check after lock
                    self._change_state(CircuitState.HALF_OPEN, "Recovery timeout reached")
        
        # Fail fast if circuit is open
        if self._state == CircuitState.OPEN:
            raise CircuitBreakerError(
                f"Circuit breaker '{self.name}' is OPEN - too many recent failures",
                failure_count=self._metrics.failed_calls
            )
        
        # Execute the function
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            duration = time.time() - start_time
            
            # Record success
            self._record_call(success=True, duration=duration)
            
            # Handle half-open state
            if self._state == CircuitState.HALF_OPEN:
                with self._lock:
                    self._half_open_success_count += 1
                    if self._half_open_success_count >= self.config.success_threshold:
                        self._change_state(CircuitState.CLOSED, "Sufficient successes in half-open state")
            
            return result
            
        except Exception as e:
            duration = time.time() - start_time
            
            # Record failure
            self._record_call(success=False, duration=duration)
            
            # Check if we should trip the circuit
            with self._lock:
                if self._state == CircuitState.CLOSED and self._should_trip_circuit():
                    self._change_state(CircuitState.OPEN, "Failure threshold exceeded")
                elif self._state == CircuitState.HALF_OPEN:
                    self._change_state(CircuitState.OPEN, "Failure in half-open state")
            
            raise
    
    async def async_call(self, coro_func: Callable, *args, **kwargs) -> Any:
        """Execute async function through circuit breaker"""
        # Check if circuit should attempt reset
        if self._state == CircuitState.OPEN and self._should_attempt_reset():
            with self._lock:
                if self._state == CircuitState.OPEN:  # Double-check after lock
                    self._change_state(CircuitState.HALF_OPEN, "Recovery timeout reached")
        
        # Fail fast if circuit is open
        if self._state == CircuitState.OPEN:
            raise CircuitBreakerError(
                f"Circuit breaker '{self.name}' is OPEN - too many recent failures",
                failure_count=self._metrics.failed_calls
            )
        
        # Execute the async function
        start_time = time.time()
        try:
            result = await coro_func(*args, **kwargs)
            duration = time.time() - start_time
            
            # Record success
            self._record_call(success=True, duration=duration)
            
            # Handle half-open state
            if self._state == CircuitState.HALF_OPEN:
                with self._lock:
                    self._half_open_success_count += 1
                    if self._half_open_success_count >= self.config.success_threshold:
                        self._change_state(CircuitState.CLOSED, "Sufficient successes in half-open state")
            
            return result
            
        except Exception as e:
            duration = time.time() - start_time
            
            # Record failure
            self._record_call(success=False, duration=duration)
            
            # Check if we should trip the circuit
            with self._lock:
                if self._state == CircuitState.CLOSED and self._should_trip_circuit():
                    self._change_state(CircuitState.OPEN, "Failure threshold exceeded")
                elif self._state == CircuitState.HALF_OPEN:
                    self._change_state(CircuitState.OPEN, "Failure in half-open state")
            
            raise
    
    def reset(self) -> None:
        """Manually reset the circuit breaker"""
        with self._lock:
            self._change_state(CircuitState.CLOSED, "Manual reset")
            self._half_open_success_count = 0
    
    def force_open(self) -> None:
        """Manually open the circuit breaker"""
        with self._lock:
            self._change_state(CircuitState.OPEN, "Manual open")
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get health status for monitoring"""
        metrics = self.metrics
        
        success_rate = 0
        if metrics.total_calls > 0:
            success_rate = (metrics.successful_calls / metrics.total_calls) * 100
        
        slow_call_rate = 0
        if metrics.total_calls > 0:
            slow_call_rate = (metrics.slow_calls / metrics.total_calls) * 100
        
        return {
            'name': self.name,
            'state': self._state.value,
            'metrics': {
                'total_calls': metrics.total_calls,
                'success_rate': f"{success_rate:.1f}%",
                'slow_call_rate': f"{slow_call_rate:.1f}%",
                'last_state_change': metrics.state_change_time
            },
            'config': {
                'failure_threshold': self.config.failure_threshold,
                'recovery_timeout': self.config.recovery_timeout,
                'success_threshold': self.config.success_threshold
            },
            'healthy': self._state != CircuitState.OPEN
        }


class CircuitBreakerManager:
    """Manages multiple circuit breakers"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self._circuit_breakers: Dict[str, EnhancedCircuitBreaker] = {}
        self._lock = threading.RLock()
    
    def get_circuit_breaker(self, name: str, config: Optional[CircuitBreakerConfig] = None) -> EnhancedCircuitBreaker:
        """Get or create a circuit breaker"""
        with self._lock:
            if name not in self._circuit_breakers:
                self._circuit_breakers[name] = EnhancedCircuitBreaker(name, config)
                self.logger.info(f"Created circuit breaker: {name}")
            return self._circuit_breakers[name]
    
    def remove_circuit_breaker(self, name: str) -> bool:
        """Remove a circuit breaker"""
        with self._lock:
            if name in self._circuit_breakers:
                del self._circuit_breakers[name]
                self.logger.info(f"Removed circuit breaker: {name}")
                return True
            return False
    
    def get_all_health_status(self) -> Dict[str, Any]:
        """Get health status of all circuit breakers"""
        with self._lock:
            return {
                'circuit_breakers': {
                    name: cb.get_health_status() 
                    for name, cb in self._circuit_breakers.items()
                },
                'total_count': len(self._circuit_breakers),
                'healthy_count': sum(1 for cb in self._circuit_breakers.values() if cb.state != CircuitState.OPEN)
            }
    
    def reset_all(self) -> None:
        """Reset all circuit breakers"""
        with self._lock:
            for cb in self._circuit_breakers.values():
                cb.reset()
        self.logger.info("Reset all circuit breakers")


# Global circuit breaker manager
_circuit_breaker_manager: Optional[CircuitBreakerManager] = None
_manager_lock = threading.Lock()


def get_circuit_breaker_manager() -> CircuitBreakerManager:
    """Get global circuit breaker manager"""
    global _circuit_breaker_manager
    if _circuit_breaker_manager is None:
        with _manager_lock:
            if _circuit_breaker_manager is None:
                _circuit_breaker_manager = CircuitBreakerManager()
    return _circuit_breaker_manager


def circuit_breaker(name: str, config: Optional[CircuitBreakerConfig] = None):
    """Decorator for circuit breaker protection"""
    manager = get_circuit_breaker_manager()
    cb = manager.get_circuit_breaker(name, config)
    
    def decorator(func):
        if asyncio.iscoroutinefunction(func):
            async def async_wrapper(*args, **kwargs):
                return await cb.async_call(func, *args, **kwargs)
            return async_wrapper
        else:
            def sync_wrapper(*args, **kwargs):
                return cb.call(func, *args, **kwargs)
            return sync_wrapper
    
    return decorator


# Convenience functions
def get_circuit_breaker(name: str, config: Optional[CircuitBreakerConfig] = None) -> EnhancedCircuitBreaker:
    """Get a circuit breaker instance"""
    manager = get_circuit_breaker_manager()
    return manager.get_circuit_breaker(name, config)