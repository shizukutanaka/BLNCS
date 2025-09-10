"""
Enhanced Error Recovery System
Comprehensive error handling with recovery mechanisms.
"""

import time
import random
import threading
from typing import Any, Callable, Dict, List, Optional, Type, Union
from functools import wraps
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .logger import get_logger
from .exceptions import BLNCSError


class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RecoveryStrategy(Enum):
    """Recovery strategies"""
    RETRY = "retry"
    FALLBACK = "fallback"
    CIRCUIT_BREAKER = "circuit_breaker"
    GRACEFUL_DEGRADATION = "graceful_degradation"
    MANUAL_INTERVENTION = "manual_intervention"


@dataclass
class ErrorContext:
    """Context information for error handling"""
    error_type: Type[Exception]
    error_message: str
    severity: ErrorSeverity
    operation: str
    timestamp: datetime = field(default_factory=datetime.now)
    retry_count: int = 0
    recovery_strategy: RecoveryStrategy = RecoveryStrategy.RETRY
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RetryConfig:
    """Configuration for retry logic"""
    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True
    backoff_strategy: str = "exponential"  # exponential, linear, fixed


class CircuitBreakerState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreaker:
    """Circuit breaker for external service calls"""
    name: str
    failure_threshold: int = 5
    recovery_timeout: int = 60
    success_threshold: int = 3
    
    state: CircuitBreakerState = CircuitBreakerState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: Optional[datetime] = None
    
    def can_execute(self) -> bool:
        """Check if operation can be executed"""
        if self.state == CircuitBreakerState.CLOSED:
            return True
        elif self.state == CircuitBreakerState.OPEN:
            if self.last_failure_time and \
               (datetime.now() - self.last_failure_time).seconds >= self.recovery_timeout:
                self.state = CircuitBreakerState.HALF_OPEN
                self.success_count = 0
                return True
            return False
        else:  # HALF_OPEN
            return True
    
    def record_success(self):
        """Record successful operation"""
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.success_threshold:
                self.state = CircuitBreakerState.CLOSED
                self.failure_count = 0
        elif self.state == CircuitBreakerState.CLOSED:
            self.failure_count = max(0, self.failure_count - 1)
    
    def record_failure(self):
        """Record failed operation"""
        self.failure_count += 1
        self.last_failure_time = datetime.now()
        
        if self.state == CircuitBreakerState.CLOSED:
            if self.failure_count >= self.failure_threshold:
                self.state = CircuitBreakerState.OPEN
        elif self.state == CircuitBreakerState.HALF_OPEN:
            self.state = CircuitBreakerState.OPEN
            self.success_count = 0


class ErrorRecoveryManager:
    """Comprehensive error recovery manager"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.error_history: List[ErrorContext] = []
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.fallback_handlers: Dict[str, Callable] = {}
        self.lock = threading.RLock()
        
        # Error type mappings to recovery strategies
        self.recovery_strategies: Dict[Type[Exception], RecoveryStrategy] = {
            ConnectionError: RecoveryStrategy.CIRCUIT_BREAKER,
            TimeoutError: RecoveryStrategy.RETRY,
            ValueError: RecoveryStrategy.GRACEFUL_DEGRADATION,
            FileNotFoundError: RecoveryStrategy.FALLBACK,
            PermissionError: RecoveryStrategy.MANUAL_INTERVENTION,
            BLNCSError: RecoveryStrategy.RETRY
        }
        
        # Default retry configurations by error type
        self.retry_configs: Dict[Type[Exception], RetryConfig] = {
            ConnectionError: RetryConfig(max_attempts=5, base_delay=2.0, max_delay=30.0),
            TimeoutError: RetryConfig(max_attempts=3, base_delay=1.0, max_delay=10.0),
            BLNCSError: RetryConfig(max_attempts=2, base_delay=0.5, max_delay=5.0)
        }
    
    def register_circuit_breaker(self, name: str, config: Dict[str, Any] = None) -> CircuitBreaker:
        """Register a circuit breaker"""
        if config is None:
            config = {}
        
        circuit_breaker = CircuitBreaker(
            name=name,
            failure_threshold=config.get('failure_threshold', 5),
            recovery_timeout=config.get('recovery_timeout', 60),
            success_threshold=config.get('success_threshold', 3)
        )
        
        with self.lock:
            self.circuit_breakers[name] = circuit_breaker
        
        self.logger.info(f"Registered circuit breaker: {name}")
        return circuit_breaker
    
    def register_fallback_handler(self, operation: str, handler: Callable):
        """Register fallback handler for an operation"""
        with self.lock:
            self.fallback_handlers[operation] = handler
        
        self.logger.info(f"Registered fallback handler for: {operation}")
    
    def get_retry_config(self, error_type: Type[Exception]) -> RetryConfig:
        """Get retry configuration for error type"""
        return self.retry_configs.get(error_type, RetryConfig())
    
    def calculate_delay(self, attempt: int, config: RetryConfig) -> float:
        """Calculate delay for retry attempt"""
        if config.backoff_strategy == "exponential":
            delay = config.base_delay * (config.exponential_base ** (attempt - 1))
        elif config.backoff_strategy == "linear":
            delay = config.base_delay * attempt
        else:  # fixed
            delay = config.base_delay
        
        # Apply jitter to prevent thundering herd
        if config.jitter:
            delay *= (0.5 + random.random())
        
        return min(delay, config.max_delay)
    
    def record_error(self, error: Exception, operation: str, metadata: Dict[str, Any] = None) -> ErrorContext:
        """Record error occurrence"""
        severity = self._classify_error_severity(error)
        recovery_strategy = self.recovery_strategies.get(type(error), RecoveryStrategy.RETRY)
        
        error_context = ErrorContext(
            error_type=type(error),
            error_message=str(error),
            severity=severity,
            operation=operation,
            recovery_strategy=recovery_strategy,
            metadata=metadata or {}
        )
        
        with self.lock:
            self.error_history.append(error_context)
            # Keep only last 1000 errors
            if len(self.error_history) > 1000:
                self.error_history = self.error_history[-1000:]
        
        self.logger.error(f"Error recorded - Operation: {operation}, Error: {error}, Severity: {severity.value}")
        return error_context
    
    def _classify_error_severity(self, error: Exception) -> ErrorSeverity:
        """Classify error severity"""
        if isinstance(error, (SystemExit, KeyboardInterrupt)):
            return ErrorSeverity.CRITICAL
        elif isinstance(error, (ConnectionError, TimeoutError)):
            return ErrorSeverity.HIGH
        elif isinstance(error, (ValueError, TypeError)):
            return ErrorSeverity.MEDIUM
        else:
            return ErrorSeverity.LOW
    
    def should_retry(self, error_context: ErrorContext, max_retries: int = None) -> bool:
        """Determine if operation should be retried"""
        if error_context.recovery_strategy != RecoveryStrategy.RETRY:
            return False
        
        retry_config = self.get_retry_config(error_context.error_type)
        max_attempts = max_retries or retry_config.max_attempts
        
        return error_context.retry_count < max_attempts
    
    def get_circuit_breaker(self, name: str) -> Optional[CircuitBreaker]:
        """Get circuit breaker by name"""
        with self.lock:
            return self.circuit_breakers.get(name)
    
    def execute_with_recovery(self, operation: Callable, operation_name: str, 
                            circuit_breaker_name: str = None, **kwargs) -> Any:
        """Execute operation with automatic recovery"""
        circuit_breaker = None
        if circuit_breaker_name:
            circuit_breaker = self.get_circuit_breaker(circuit_breaker_name)
            if not circuit_breaker:
                circuit_breaker = self.register_circuit_breaker(circuit_breaker_name)
        
        last_error = None
        attempt = 0
        
        while True:
            attempt += 1
            
            # Check circuit breaker
            if circuit_breaker and not circuit_breaker.can_execute():
                self.logger.warning(f"Circuit breaker {circuit_breaker_name} is OPEN")
                raise BLNCSError(f"Service {circuit_breaker_name} is temporarily unavailable")
            
            try:
                result = operation(**kwargs)
                
                # Record success
                if circuit_breaker:
                    circuit_breaker.record_success()
                
                if attempt > 1:
                    self.logger.info(f"Operation {operation_name} succeeded after {attempt} attempts")
                
                return result
                
            except Exception as error:
                last_error = error
                error_context = self.record_error(error, operation_name)
                error_context.retry_count = attempt - 1
                
                # Record failure
                if circuit_breaker:
                    circuit_breaker.record_failure()
                
                # Check if should retry
                if not self.should_retry(error_context):
                    break
                
                # Calculate delay
                retry_config = self.get_retry_config(type(error))
                delay = self.calculate_delay(attempt, retry_config)
                
                self.logger.warning(f"Operation {operation_name} failed (attempt {attempt}), retrying in {delay:.2f}s: {error}")
                time.sleep(delay)
        
        # All retries exhausted or no retry strategy
        self.logger.error(f"Operation {operation_name} failed permanently after {attempt} attempts")
        
        # Try fallback handler
        fallback_handler = self.fallback_handlers.get(operation_name)
        if fallback_handler:
            self.logger.info(f"Attempting fallback for {operation_name}")
            try:
                return fallback_handler(**kwargs)
            except Exception as fallback_error:
                self.logger.error(f"Fallback failed for {operation_name}: {fallback_error}")
        
        # Re-raise the last error
        raise last_error
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics"""
        with self.lock:
            if not self.error_history:
                return {"total_errors": 0}
            
            # Count by severity
            severity_counts = {}
            for severity in ErrorSeverity:
                severity_counts[severity.value] = sum(1 for e in self.error_history if e.severity == severity)
            
            # Count by error type
            error_type_counts = {}
            for error in self.error_history:
                error_type_name = error.error_type.__name__
                error_type_counts[error_type_name] = error_type_counts.get(error_type_name, 0) + 1
            
            # Recent errors (last hour)
            recent_cutoff = datetime.now() - timedelta(hours=1)
            recent_errors = sum(1 for e in self.error_history if e.timestamp > recent_cutoff)
            
            return {
                "total_errors": len(self.error_history),
                "recent_errors_1h": recent_errors,
                "severity_breakdown": severity_counts,
                "error_type_breakdown": error_type_counts,
                "circuit_breakers": {
                    name: {
                        "state": cb.state.value,
                        "failure_count": cb.failure_count,
                        "success_count": cb.success_count
                    }
                    for name, cb in self.circuit_breakers.items()
                }
            }


# Decorators for easy error handling

def with_retry(max_attempts: int = 3, base_delay: float = 1.0, operation_name: str = None):
    """Decorator for automatic retry logic"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            recovery_manager = get_error_recovery_manager()
            op_name = operation_name or f"{func.__module__}.{func.__name__}"
            return recovery_manager.execute_with_recovery(
                func, op_name, max_retries=max_attempts, *args, **kwargs
            )
        return wrapper
    return decorator


def with_circuit_breaker(circuit_breaker_name: str):
    """Decorator for circuit breaker pattern"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            recovery_manager = get_error_recovery_manager()
            op_name = f"{func.__module__}.{func.__name__}"
            return recovery_manager.execute_with_recovery(
                func, op_name, circuit_breaker_name, *args, **kwargs
            )
        return wrapper
    return decorator


def with_fallback(fallback_func: Callable):
    """Decorator for fallback handling"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                recovery_manager = get_error_recovery_manager()
                recovery_manager.logger.warning(f"Function {func.__name__} failed, using fallback: {e}")
                return fallback_func(*args, **kwargs)
        return wrapper
    return decorator


# Global instance
_error_recovery_manager = None

def get_error_recovery_manager() -> ErrorRecoveryManager:
    """Get global error recovery manager"""
    global _error_recovery_manager
    if _error_recovery_manager is None:
        _error_recovery_manager = ErrorRecoveryManager()
    return _error_recovery_manager