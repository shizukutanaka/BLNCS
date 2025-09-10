"""
Advanced Error Recovery and Retry Mechanisms for BLNCS
Implements sophisticated error recovery patterns with adaptive retry strategies.
"""

import time
import random
import asyncio
import threading
from typing import Dict, Any, Optional, Callable, Type, List, Union
from dataclasses import dataclass, field
from enum import Enum
import inspect
from functools import wraps
import traceback

from .logger import get_logger
from .exceptions import BLNCSError, CircuitBreakerError
from .observability import record_metric, MetricType
from .circuit_breaker_enhanced import get_circuit_breaker


class RetryStrategy(Enum):
    """Available retry strategies"""
    FIXED_DELAY = "fixed_delay"
    EXPONENTIAL_BACKOFF = "exponential_backoff" 
    LINEAR_BACKOFF = "linear_backoff"
    EXPONENTIAL_JITTER = "exponential_jitter"
    FIBONACCI_BACKOFF = "fibonacci_backoff"


class ErrorCategory(Enum):
    """Categories of errors for different recovery strategies"""
    TRANSIENT = "transient"           # Network timeouts, temporary service unavailable
    RATE_LIMITED = "rate_limited"     # Rate limiting, quota exceeded
    AUTHENTICATION = "authentication" # Auth failures, token expired
    CONFIGURATION = "configuration"   # Invalid config, missing parameters
    RESOURCE = "resource"             # Out of memory, disk space
    BUSINESS_LOGIC = "business_logic" # Invalid business state
    PERMANENT = "permanent"           # Unrecoverable errors


@dataclass
class RetryConfig:
    """Configuration for retry behavior"""
    max_attempts: int = 3
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_BACKOFF
    base_delay: float = 1.0
    max_delay: float = 60.0
    backoff_multiplier: float = 2.0
    jitter_range: float = 0.1
    retriable_exceptions: List[Type[Exception]] = field(default_factory=list)
    non_retriable_exceptions: List[Type[Exception]] = field(default_factory=list)
    circuit_breaker_enabled: bool = True
    timeout_per_attempt: Optional[float] = None


@dataclass
class RecoveryAction:
    """Recovery action configuration"""
    name: str
    handler: Callable[[Exception, Dict[str, Any]], bool]
    priority: int = 100  # Lower numbers execute first
    applicable_errors: List[Type[Exception]] = field(default_factory=list)
    max_executions: Optional[int] = None
    cooldown_seconds: float = 0.0


class AdvancedErrorRecovery:
    """Advanced error recovery system with intelligent retry strategies"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        
        # Error categorization
        self._error_categories: Dict[Type[Exception], ErrorCategory] = {}
        self._category_configs: Dict[ErrorCategory, RetryConfig] = {}
        self._setup_default_categorization()
        
        # Recovery actions
        self._recovery_actions: List[RecoveryAction] = []
        self._action_executions: Dict[str, Dict[str, Any]] = {}
        self._actions_lock = threading.RLock()
        
        # Statistics
        self._retry_stats: Dict[str, Dict[str, Any]] = {}
        self._stats_lock = threading.RLock()
        
        # Setup default recovery actions
        self._setup_default_recovery_actions()
    
    def _setup_default_categorization(self):
        """Setup default error categorization"""
        # Transient errors - usually retriable
        transient_config = RetryConfig(
            max_attempts=5,
            strategy=RetryStrategy.EXPONENTIAL_JITTER,
            base_delay=1.0,
            max_delay=30.0,
            backoff_multiplier=2.0
        )
        
        # Rate limited errors - longer delays
        rate_limited_config = RetryConfig(
            max_attempts=3,
            strategy=RetryStrategy.EXPONENTIAL_BACKOFF,
            base_delay=5.0,
            max_delay=300.0,
            backoff_multiplier=3.0
        )
        
        # Authentication errors - try once with token refresh
        auth_config = RetryConfig(
            max_attempts=2,
            strategy=RetryStrategy.FIXED_DELAY,
            base_delay=0.1,
            max_delay=1.0
        )
        
        # Configuration errors - not retriable
        config_config = RetryConfig(
            max_attempts=1,
            strategy=RetryStrategy.FIXED_DELAY,
            base_delay=0.0
        )
        
        self._category_configs = {
            ErrorCategory.TRANSIENT: transient_config,
            ErrorCategory.RATE_LIMITED: rate_limited_config,
            ErrorCategory.AUTHENTICATION: auth_config,
            ErrorCategory.CONFIGURATION: config_config,
            ErrorCategory.RESOURCE: transient_config,
            ErrorCategory.BUSINESS_LOGIC: config_config,
            ErrorCategory.PERMANENT: RetryConfig(max_attempts=1)
        }
        
        # Default error categorization
        from .exceptions import (
            ConnectionError, TimeoutError, LightningError,
            ConfigError, ValidationError, SecurityError
        )
        
        self._error_categories.update({
            ConnectionError: ErrorCategory.TRANSIENT,
            TimeoutError: ErrorCategory.TRANSIENT,
            LightningError: ErrorCategory.TRANSIENT,
            ConfigError: ErrorCategory.CONFIGURATION,
            ValidationError: ErrorCategory.CONFIGURATION,
            SecurityError: ErrorCategory.AUTHENTICATION,
            BLNCSError: ErrorCategory.BUSINESS_LOGIC,
        })
    
    def _setup_default_recovery_actions(self):
        """Setup default recovery actions"""
        
        # Token refresh for authentication errors
        def refresh_token_action(error: Exception, context: Dict[str, Any]) -> bool:
            if "token_refresh_handler" in context:
                try:
                    context["token_refresh_handler"]()
                    self.logger.info("Successfully refreshed authentication token")
                    return True
                except Exception as e:
                    self.logger.error(f"Failed to refresh token: {e}")
            return False
        
        # Clear cache for stale data errors
        def clear_cache_action(error: Exception, context: Dict[str, Any]) -> bool:
            if "cache_manager" in context:
                try:
                    cache_manager = context["cache_manager"]
                    cache_manager.clear_all()
                    self.logger.info("Cleared all caches for recovery")
                    return True
                except Exception as e:
                    self.logger.error(f"Failed to clear cache: {e}")
            return False
        
        # Reconnect for connection errors
        def reconnect_action(error: Exception, context: Dict[str, Any]) -> bool:
            if "reconnect_handler" in context:
                try:
                    context["reconnect_handler"]()
                    self.logger.info("Successfully reconnected")
                    return True
                except Exception as e:
                    self.logger.error(f"Failed to reconnect: {e}")
            return False
        
        self._recovery_actions = [
            RecoveryAction(
                name="refresh_token",
                handler=refresh_token_action,
                priority=10,
                applicable_errors=[SecurityError],
                max_executions=1,
                cooldown_seconds=5.0
            ),
            RecoveryAction(
                name="clear_cache",
                handler=clear_cache_action,
                priority=50,
                applicable_errors=[Exception],  # Apply to all errors
                max_executions=1,
                cooldown_seconds=60.0
            ),
            RecoveryAction(
                name="reconnect",
                handler=reconnect_action,
                priority=20,
                applicable_errors=[ConnectionError],
                max_executions=2,
                cooldown_seconds=10.0
            )
        ]
    
    def categorize_error(self, error: Exception) -> ErrorCategory:
        """Categorize an error for appropriate retry strategy"""
        error_type = type(error)
        
        # Check exact type match first
        if error_type in self._error_categories:
            return self._error_categories[error_type]
        
        # Check inheritance hierarchy
        for registered_type, category in self._error_categories.items():
            if isinstance(error, registered_type):
                return category
        
        # Default categorization based on common patterns
        error_msg = str(error).lower()
        
        if any(keyword in error_msg for keyword in 
               ['timeout', 'connection', 'network', 'temporary', 'unavailable']):
            return ErrorCategory.TRANSIENT
        elif any(keyword in error_msg for keyword in 
                ['rate limit', 'quota', 'throttle', 'too many']):
            return ErrorCategory.RATE_LIMITED
        elif any(keyword in error_msg for keyword in 
                ['auth', 'token', 'credential', 'permission', 'unauthorized']):
            return ErrorCategory.AUTHENTICATION
        elif any(keyword in error_msg for keyword in 
                ['config', 'invalid', 'missing', 'required']):
            return ErrorCategory.CONFIGURATION
        
        return ErrorCategory.BUSINESS_LOGIC
    
    def calculate_delay(self, attempt: int, config: RetryConfig) -> float:
        """Calculate delay for next retry attempt"""
        if config.strategy == RetryStrategy.FIXED_DELAY:
            delay = config.base_delay
        
        elif config.strategy == RetryStrategy.LINEAR_BACKOFF:
            delay = config.base_delay * attempt
        
        elif config.strategy == RetryStrategy.EXPONENTIAL_BACKOFF:
            delay = config.base_delay * (config.backoff_multiplier ** (attempt - 1))
        
        elif config.strategy == RetryStrategy.FIBONACCI_BACKOFF:
            fib_sequence = [1, 1]
            for i in range(2, attempt + 1):
                fib_sequence.append(fib_sequence[-1] + fib_sequence[-2])
            delay = config.base_delay * fib_sequence[min(attempt - 1, len(fib_sequence) - 1)]
        
        elif config.strategy == RetryStrategy.EXPONENTIAL_JITTER:
            base_delay = config.base_delay * (config.backoff_multiplier ** (attempt - 1))
            jitter = base_delay * config.jitter_range * (2 * random.random() - 1)
            delay = base_delay + jitter
        
        else:
            delay = config.base_delay
        
        return min(delay, config.max_delay)
    
    def should_retry(self, error: Exception, attempt: int, config: RetryConfig) -> bool:
        """Determine if error should be retried"""
        if attempt >= config.max_attempts:
            return False
        
        # Check non-retriable exceptions
        if config.non_retriable_exceptions:
            for non_retriable in config.non_retriable_exceptions:
                if isinstance(error, non_retriable):
                    return False
        
        # Check retriable exceptions (if specified, only these are retriable)
        if config.retriable_exceptions:
            for retriable in config.retriable_exceptions:
                if isinstance(error, retriable):
                    return True
            return False
        
        # Default: categorize and decide
        category = self.categorize_error(error)
        return category in [ErrorCategory.TRANSIENT, ErrorCategory.RATE_LIMITED, ErrorCategory.AUTHENTICATION]
    
    def _execute_recovery_actions(self, error: Exception, context: Dict[str, Any]) -> bool:
        """Execute applicable recovery actions"""
        error_type = type(error)
        applicable_actions = []
        
        # Find applicable recovery actions
        for action in self._recovery_actions:
            if not action.applicable_errors or any(
                isinstance(error, applicable_type) or error_type == applicable_type
                for applicable_type in action.applicable_errors
            ):
                applicable_actions.append(action)
        
        # Sort by priority
        applicable_actions.sort(key=lambda a: a.priority)
        
        recovery_successful = False
        
        with self._actions_lock:
            for action in applicable_actions:
                # Check execution limits and cooldown
                action_key = f"{action.name}_{type(error).__name__}"
                action_info = self._action_executions.get(action_key, {
                    'count': 0,
                    'last_execution': 0
                })
                
                current_time = time.time()
                
                # Check cooldown
                if (current_time - action_info['last_execution']) < action.cooldown_seconds:
                    continue
                
                # Check max executions
                if (action.max_executions is not None and 
                    action_info['count'] >= action.max_executions):
                    continue
                
                # Execute recovery action
                try:
                    self.logger.info(f"Executing recovery action: {action.name}")
                    success = action.handler(error, context)
                    
                    # Update execution tracking
                    self._action_executions[action_key] = {
                        'count': action_info['count'] + 1,
                        'last_execution': current_time
                    }
                    
                    if success:
                        recovery_successful = True
                        record_metric(f"recovery.action.{action.name}.success", 1, MetricType.COUNTER)
                        self.logger.info(f"Recovery action {action.name} succeeded")
                        break  # Stop after first successful recovery
                    else:
                        record_metric(f"recovery.action.{action.name}.failed", 1, MetricType.COUNTER)
                        
                except Exception as recovery_error:
                    self.logger.error(f"Recovery action {action.name} failed: {recovery_error}")
                    record_metric(f"recovery.action.{action.name}.error", 1, MetricType.COUNTER)
        
        return recovery_successful
    
    def _record_retry_stats(self, func_name: str, attempt: int, success: bool, 
                           error: Optional[Exception], delay: float):
        """Record retry statistics"""
        with self._stats_lock:
            if func_name not in self._retry_stats:
                self._retry_stats[func_name] = {
                    'total_attempts': 0,
                    'total_successes': 0,
                    'total_failures': 0,
                    'total_delay': 0.0,
                    'error_types': {},
                    'avg_attempts_to_success': 0.0
                }
            
            stats = self._retry_stats[func_name]
            stats['total_attempts'] += 1
            stats['total_delay'] += delay
            
            if success:
                stats['total_successes'] += 1
                # Update average attempts to success
                success_count = stats['total_successes']
                stats['avg_attempts_to_success'] = (
                    (stats['avg_attempts_to_success'] * (success_count - 1) + attempt) / success_count
                )
            else:
                stats['total_failures'] += 1
                
                if error:
                    error_type = type(error).__name__
                    stats['error_types'][error_type] = stats['error_types'].get(error_type, 0) + 1
    
    def retry_with_recovery(self, func: Callable, *args, recovery_context: Dict[str, Any] = None,
                           retry_config: Optional[RetryConfig] = None, **kwargs) -> Any:
        """Execute function with advanced retry and recovery"""
        recovery_context = recovery_context or {}
        func_name = func.__name__ if hasattr(func, '__name__') else str(func)
        
        last_error = None
        attempt = 0
        
        while True:
            attempt += 1
            
            try:
                # Execute function with timeout if configured
                if retry_config and retry_config.timeout_per_attempt:
                    # Note: This is a simplified timeout implementation
                    # In production, you might want to use asyncio timeout or thread-based timeout
                    result = func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)
                
                # Success - record stats and return
                self._record_retry_stats(func_name, attempt, True, None, 0.0)
                
                if attempt > 1:
                    self.logger.info(f"Function {func_name} succeeded after {attempt} attempts")
                    record_metric(f"retry.success.{func_name}", attempt, MetricType.GAUGE)
                
                return result
            
            except Exception as error:
                last_error = error
                
                # Determine retry configuration
                if retry_config is None:
                    category = self.categorize_error(error)
                    config = self._category_configs[category]
                else:
                    config = retry_config
                
                # Check if we should retry
                if not self.should_retry(error, attempt, config):
                    self.logger.error(f"Function {func_name} failed permanently after {attempt} attempts: {error}")
                    self._record_retry_stats(func_name, attempt, False, error, 0.0)
                    record_metric(f"retry.failure.{func_name}", attempt, MetricType.GAUGE)
                    raise
                
                # Execute recovery actions before retry
                recovery_attempted = self._execute_recovery_actions(error, recovery_context)
                
                # Calculate delay
                delay = self.calculate_delay(attempt, config)
                
                self.logger.warning(
                    f"Function {func_name} failed (attempt {attempt}/{config.max_attempts}): {error}. "
                    f"Retrying in {delay:.2f}s. Recovery attempted: {recovery_attempted}"
                )
                
                # Record retry attempt
                record_metric(f"retry.attempt.{func_name}", 1, MetricType.COUNTER)
                self._record_retry_stats(func_name, attempt, False, error, delay)
                
                # Wait before retry
                if delay > 0:
                    time.sleep(delay)
        
        # This should never be reached, but just in case
        if last_error:
            raise last_error
    
    async def async_retry_with_recovery(self, coro_func: Callable, *args, 
                                       recovery_context: Dict[str, Any] = None,
                                       retry_config: Optional[RetryConfig] = None, **kwargs) -> Any:
        """Async version of retry with recovery"""
        recovery_context = recovery_context or {}
        func_name = coro_func.__name__ if hasattr(coro_func, '__name__') else str(coro_func)
        
        last_error = None
        attempt = 0
        
        while True:
            attempt += 1
            
            try:
                # Execute async function with timeout if configured
                if retry_config and retry_config.timeout_per_attempt:
                    result = await asyncio.wait_for(
                        coro_func(*args, **kwargs),
                        timeout=retry_config.timeout_per_attempt
                    )
                else:
                    result = await coro_func(*args, **kwargs)
                
                # Success - record stats and return
                self._record_retry_stats(func_name, attempt, True, None, 0.0)
                
                if attempt > 1:
                    self.logger.info(f"Async function {func_name} succeeded after {attempt} attempts")
                    record_metric(f"async_retry.success.{func_name}", attempt, MetricType.GAUGE)
                
                return result
            
            except Exception as error:
                last_error = error
                
                # Determine retry configuration
                if retry_config is None:
                    category = self.categorize_error(error)
                    config = self._category_configs[category]
                else:
                    config = retry_config
                
                # Check if we should retry
                if not self.should_retry(error, attempt, config):
                    self.logger.error(f"Async function {func_name} failed permanently after {attempt} attempts: {error}")
                    self._record_retry_stats(func_name, attempt, False, error, 0.0)
                    record_metric(f"async_retry.failure.{func_name}", attempt, MetricType.GAUGE)
                    raise
                
                # Execute recovery actions before retry
                recovery_attempted = self._execute_recovery_actions(error, recovery_context)
                
                # Calculate delay
                delay = self.calculate_delay(attempt, config)
                
                self.logger.warning(
                    f"Async function {func_name} failed (attempt {attempt}/{config.max_attempts}): {error}. "
                    f"Retrying in {delay:.2f}s. Recovery attempted: {recovery_attempted}"
                )
                
                # Record retry attempt
                record_metric(f"async_retry.attempt.{func_name}", 1, MetricType.COUNTER)
                self._record_retry_stats(func_name, attempt, False, error, delay)
                
                # Wait before retry (async)
                if delay > 0:
                    await asyncio.sleep(delay)
        
        # This should never be reached, but just in case
        if last_error:
            raise last_error
    
    def register_error_category(self, error_type: Type[Exception], category: ErrorCategory):
        """Register custom error categorization"""
        self._error_categories[error_type] = category
        self.logger.debug(f"Registered error type {error_type.__name__} as {category.value}")
    
    def register_recovery_action(self, action: RecoveryAction):
        """Register custom recovery action"""
        self._recovery_actions.append(action)
        self._recovery_actions.sort(key=lambda a: a.priority)
        self.logger.info(f"Registered recovery action: {action.name}")
    
    def get_retry_stats(self) -> Dict[str, Any]:
        """Get retry statistics"""
        with self._stats_lock:
            return {
                'function_stats': self._retry_stats.copy(),
                'total_functions': len(self._retry_stats),
                'recovery_actions': len(self._recovery_actions)
            }


# Global error recovery instance
_error_recovery: Optional[AdvancedErrorRecovery] = None
_recovery_lock = threading.Lock()


def get_error_recovery() -> AdvancedErrorRecovery:
    """Get global error recovery instance"""
    global _error_recovery
    if _error_recovery is None:
        with _recovery_lock:
            if _error_recovery is None:
                _error_recovery = AdvancedErrorRecovery()
    return _error_recovery


# Decorator functions
def retry_with_recovery(retry_config: Optional[RetryConfig] = None, 
                       recovery_context: Dict[str, Any] = None):
    """Decorator for automatic retry with recovery"""
    def decorator(func):
        if asyncio.iscoroutinefunction(func):
            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                recovery = get_error_recovery()
                return await recovery.async_retry_with_recovery(
                    func, *args, recovery_context=recovery_context, 
                    retry_config=retry_config, **kwargs
                )
            return async_wrapper
        else:
            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                recovery = get_error_recovery()
                return recovery.retry_with_recovery(
                    func, *args, recovery_context=recovery_context,
                    retry_config=retry_config, **kwargs
                )
            return sync_wrapper
    
    return decorator


# Convenience functions
def execute_with_retry(func: Callable, *args, retry_config: Optional[RetryConfig] = None,
                      recovery_context: Dict[str, Any] = None, **kwargs) -> Any:
    """Execute function with retry and recovery"""
    recovery = get_error_recovery()
    return recovery.retry_with_recovery(func, *args, recovery_context=recovery_context,
                                       retry_config=retry_config, **kwargs)


async def async_execute_with_retry(coro_func: Callable, *args, retry_config: Optional[RetryConfig] = None,
                                  recovery_context: Dict[str, Any] = None, **kwargs) -> Any:
    """Execute async function with retry and recovery"""
    recovery = get_error_recovery()
    return await recovery.async_retry_with_recovery(coro_func, *args, recovery_context=recovery_context,
                                                   retry_config=retry_config, **kwargs)


# Legacy compatibility functions
def get_error_recovery_manager():
    """Compatibility function for legacy code."""
    return get_error_recovery()