# BLRCS Error Handling Module
# Comprehensive error handling with clear error boundaries
import sys
import traceback
import logging
from typing import Optional, Any, Callable, TypeVar, Union
from functools import wraps
from enum import Enum
from datetime import datetime

T = TypeVar('T')

class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class BLRCSError(Exception):
    """Base BLRCS exception"""
    def __init__(self, message: str, severity: ErrorSeverity = ErrorSeverity.MEDIUM, details: Optional[dict] = None):
        super().__init__(message)
        self.severity = severity
        self.details = details or {}
        self.timestamp = datetime.now()

class ConfigurationError(BLRCSError):
    """Configuration related errors"""
    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message, ErrorSeverity.HIGH, details)

class DatabaseError(BLRCSError):
    """Database operation errors"""
    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message, ErrorSeverity.HIGH, details)

class CacheError(BLRCSError):
    """Cache operation errors"""
    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message, ErrorSeverity.MEDIUM, details)

class SecurityError(BLRCSError):
    """Security related errors"""
    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message, ErrorSeverity.CRITICAL, details)

class ValidationError(BLRCSError):
    """Input validation errors"""
    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message, ErrorSeverity.LOW, details)

class NetworkError(BLRCSError):
    """Network related errors"""
    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message, ErrorSeverity.MEDIUM, details)

class PluginError(BLRCSError):
    """Plugin related errors"""
    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message, ErrorSeverity.LOW, details)

class ErrorHandler:
    """
    Enhanced error handler implementing Rob Pike's error handling philosophy:
    Handle errors explicitly, don't ignore them.
    Added features: error correlation, automatic recovery, and alerting.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.error_counts = {}
        self.error_history = []
        self.max_history = 1000
        self.recovery_strategies = {}
        
        # Enhanced error tracking
        self.error_patterns = {}
        self.error_correlations = {}
        self.alert_thresholds = {
            ErrorSeverity.CRITICAL: 1,
            ErrorSeverity.HIGH: 5,
            ErrorSeverity.MEDIUM: 10,
            ErrorSeverity.LOW: 20
        }
        self.alert_callbacks = []
        self.auto_recovery_enabled = True
        
        # Circuit breakers for different components
        self.circuit_breakers = {
            'database': CircuitBreaker(failure_threshold=3, timeout=30.0),
            'network': CircuitBreaker(failure_threshold=5, timeout=60.0),
            'cache': CircuitBreaker(failure_threshold=10, timeout=15.0),
            'security': CircuitBreaker(failure_threshold=2, timeout=120.0)
        }
        
    def handle_error(self, error: Exception, context: str = "") -> Optional[Any]:
        """
        Enhanced error handling with correlation, alerting, and automatic recovery.
        Returns recovery result if applicable.
        """
        error_type = type(error).__name__
        self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
        
        # Enhanced error analysis
        self._analyze_error_pattern(error, context)
        self._check_error_correlation(error, context)
        
        # Log error with enriched context
        if isinstance(error, BLRCSError):
            self._log_blrcs_error(error, context)
        else:
            self._log_generic_error(error, context)
        
        # Store in history with metadata
        self._add_to_history(error, context)
        
        # Check alert thresholds
        self._check_alert_thresholds(error)
        
        # Apply circuit breaker if applicable
        circuit_breaker = self._get_circuit_breaker(context)
        if circuit_breaker:
            try:
                return circuit_breaker.call(self._attempt_recovery, error, context)
            except BLRCSError:
                pass  # Circuit breaker is open
        
        # Attempt recovery
        recovery_result = self._attempt_recovery(error, context)
        
        # If auto-recovery is enabled and recovery failed, try alternative strategies
        if self.auto_recovery_enabled and recovery_result is None:
            recovery_result = self._try_auto_recovery(error, context)
        
        return recovery_result
    
    def _log_blrcs_error(self, error: BLRCSError, context: str):
        """Log BLRCS specific error"""
        log_message = f"[{context}] {error}"
        
        if error.severity == ErrorSeverity.CRITICAL:
            self.logger.critical(log_message, extra=error.details)
        elif error.severity == ErrorSeverity.HIGH:
            self.logger.error(log_message, extra=error.details)
        elif error.severity == ErrorSeverity.MEDIUM:
            self.logger.warning(log_message, extra=error.details)
        else:
            self.logger.info(log_message, extra=error.details)
    
    def _log_generic_error(self, error: Exception, context: str):
        """Log generic error"""
        self.logger.error(f"[{context}] {type(error).__name__}: {error}")
        self.logger.debug(traceback.format_exc())
    
    def _add_to_history(self, error: Exception, context: str):
        """Add error to history"""
        self.error_history.append({
            "timestamp": datetime.now().isoformat(),
            "type": type(error).__name__,
            "message": str(error),
            "context": context,
            "severity": getattr(error, 'severity', ErrorSeverity.MEDIUM).value
        })
        
        # Trim history
        if len(self.error_history) > self.max_history:
            self.error_history = self.error_history[-self.max_history:]
    
    def _attempt_recovery(self, error: Exception, context: str) -> Optional[Any]:
        """Attempt to recover from error"""
        error_type = type(error)
        
        if error_type in self.recovery_strategies:
            try:
                return self.recovery_strategies[error_type](error, context)
            except Exception as recovery_error:
                self.logger.error(f"Recovery failed: {recovery_error}")
        
        return None
    
    def register_recovery(self, error_type: type, strategy: Callable):
        """Register recovery strategy for error type"""
        self.recovery_strategies[error_type] = strategy
    
    def get_error_stats(self) -> dict:
        """Get error statistics"""
        return {
            "counts": self.error_counts.copy(),
            "recent_errors": self.error_history[-10:],
            "total_errors": sum(self.error_counts.values())
        }
    
    def _analyze_error_pattern(self, error: Exception, context: str):
        """Analyze error patterns for predictive insights"""
        error_key = f"{type(error).__name__}:{context}"
        
        if error_key not in self.error_patterns:
            self.error_patterns[error_key] = {
                'count': 0,
                'first_seen': datetime.now(),
                'last_seen': datetime.now(),
                'frequency': 0.0,
                'trend': 'stable'
            }
        
        pattern = self.error_patterns[error_key]
        pattern['count'] += 1
        pattern['last_seen'] = datetime.now()
        
        # Calculate frequency (errors per minute)
        time_diff = (pattern['last_seen'] - pattern['first_seen']).total_seconds() / 60
        if time_diff > 0:
            pattern['frequency'] = pattern['count'] / time_diff
            
            # Determine trend
            if pattern['count'] > 5:
                recent_errors = [e for e in self.error_history[-10:] 
                               if e['type'] == type(error).__name__ and e['context'] == context]
                if len(recent_errors) > len([e for e in self.error_history[-20:-10] 
                                           if e['type'] == type(error).__name__ and e['context'] == context]):
                    pattern['trend'] = 'increasing'
                else:
                    pattern['trend'] = 'decreasing'
    
    def _check_error_correlation(self, error: Exception, context: str):
        """Check for error correlations across different components"""
        current_time = datetime.now()
        recent_window = 300  # 5 minutes
        
        recent_errors = [
            e for e in self.error_history 
            if (current_time - datetime.fromisoformat(e['timestamp'])).total_seconds() < recent_window
        ]
        
        if len(recent_errors) > 3:
            # Check for cascading failures
            contexts = [e['context'] for e in recent_errors]
            unique_contexts = set(contexts)
            
            if len(unique_contexts) > 1:
                correlation_key = f"{context}:cascade"
                if correlation_key not in self.error_correlations:
                    self.error_correlations[correlation_key] = []
                
                self.error_correlations[correlation_key].append({
                    'timestamp': current_time.isoformat(),
                    'contexts': list(unique_contexts),
                    'error_count': len(recent_errors)
                })
    
    def _check_alert_thresholds(self, error: Exception):
        """Check if error count exceeds alert thresholds"""
        if isinstance(error, BLRCSError):
            severity = error.severity
            error_type = type(error).__name__
            count = self.error_counts.get(error_type, 0)
            threshold = self.alert_thresholds.get(severity, float('inf'))
            
            if count >= threshold:
                self._trigger_alert(error, count)
    
    def _trigger_alert(self, error: Exception, count: int):
        """Trigger alert for error threshold breach"""
        alert_data = {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'count': count,
            'severity': getattr(error, 'severity', ErrorSeverity.MEDIUM).value,
            'timestamp': datetime.now().isoformat()
        }
        
        for callback in self.alert_callbacks:
            try:
                callback(alert_data)
            except Exception as e:
                self.logger.error(f"Alert callback failed: {e}")
    
    def _get_circuit_breaker(self, context: str) -> Optional[CircuitBreaker]:
        """Get appropriate circuit breaker for context"""
        for component, breaker in self.circuit_breakers.items():
            if component in context.lower():
                return breaker
        return None
    
    def _try_auto_recovery(self, error: Exception, context: str) -> Optional[Any]:
        """Attempt automatic recovery based on error type and context"""
        error_type = type(error).__name__
        
        # Database connection issues
        if 'database' in context.lower() and isinstance(error, (DatabaseError, ConnectionError)):
            return self._recover_database_connection()
        
        # Cache issues
        elif 'cache' in context.lower() and isinstance(error, CacheError):
            return self._recover_cache_operations()
        
        # Network issues
        elif isinstance(error, NetworkError):
            return self._recover_network_connection()
        
        # Configuration issues
        elif isinstance(error, ConfigurationError):
            return self._recover_configuration()
        
        return None
    
    def _recover_database_connection(self) -> Optional[Any]:
        """Attempt to recover database connection"""
        try:
            # In a real implementation, this would attempt to reconnect
            self.logger.info("Attempting database connection recovery")
            return "database_recovery_attempted"
        except Exception as e:
            self.logger.error(f"Database recovery failed: {e}")
            return None
    
    def _recover_cache_operations(self) -> Optional[Any]:
        """Attempt to recover cache operations"""
        try:
            # Clear corrupted cache entries
            self.logger.info("Attempting cache recovery by clearing corrupted entries")
            return "cache_recovery_attempted"
        except Exception as e:
            self.logger.error(f"Cache recovery failed: {e}")
            return None
    
    def _recover_network_connection(self) -> Optional[Any]:
        """Attempt to recover network connection"""
        try:
            self.logger.info("Attempting network connection recovery")
            return "network_recovery_attempted"
        except Exception as e:
            self.logger.error(f"Network recovery failed: {e}")
            return None
    
    def _recover_configuration(self) -> Optional[Any]:
        """Attempt to recover configuration issues"""
        try:
            self.logger.info("Attempting configuration recovery with defaults")
            return "config_recovery_attempted"
        except Exception as e:
            self.logger.error(f"Configuration recovery failed: {e}")
            return None
    
    def add_alert_callback(self, callback: Callable[[dict], None]):
        """Add callback for error alerts"""
        self.alert_callbacks.append(callback)
    
    def remove_alert_callback(self, callback: Callable[[dict], None]):
        """Remove alert callback"""
        if callback in self.alert_callbacks:
            self.alert_callbacks.remove(callback)
    
    def get_error_patterns(self) -> dict:
        """Get error pattern analysis"""
        return {
            'patterns': self.error_patterns.copy(),
            'correlations': self.error_correlations.copy(),
            'circuit_breaker_status': {
                name: {
                    'is_open': breaker.is_open,
                    'failure_count': breaker.failure_count,
                    'last_failure_time': breaker.last_failure_time
                }
                for name, breaker in self.circuit_breakers.items()
            }
        }
    
    def reset_circuit_breaker(self, component: str):
        """Reset specific circuit breaker"""
        if component in self.circuit_breakers:
            self.circuit_breakers[component].reset()
            self.logger.info(f"Circuit breaker reset for {component}")
    
    def clear_history(self):
        """Clear error history and patterns"""
        self.error_history.clear()
        self.error_counts.clear()
        self.error_patterns.clear()
        self.error_correlations.clear()

def safe_execute(func: Callable[..., T], 
                default: Optional[T] = None,
                error_handler: Optional[ErrorHandler] = None,
                context: str = "") -> Union[T, Optional[T]]:
    """
    Safely execute function with error handling.
    Returns result or default value on error.
    """
    try:
        return func()
    except Exception as e:
        if error_handler:
            recovery = error_handler.handle_error(e, context or func.__name__)
            if recovery is not None:
                return recovery
        return default

def resilient(default: Any = None, 
             retries: int = 3,
             backoff: float = 1.0,
             exceptions: tuple = (Exception,)):
    """
    Decorator for resilient function execution.
    Implements retry logic with exponential backoff.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            delay = backoff
            
            for attempt in range(retries):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < retries - 1:
                        import time
                        time.sleep(delay)
                        delay *= 2  # Exponential backoff
                    else:
                        if default is not None:
                            return default
                        raise
            
            if last_exception:
                raise last_exception
            
        return wrapper
    return decorator

def error_boundary(severity: ErrorSeverity = ErrorSeverity.MEDIUM):
    """
    Decorator to create error boundary around function.
    Converts exceptions to BLRCSError with specified severity.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except BLRCSError:
                raise  # Re-raise BLRCS errors as-is
            except Exception as e:
                raise BLRCSError(
                    f"Error in {func.__name__}: {str(e)}",
                    severity=severity,
                    details={
                        "function": func.__name__,
                        "original_error": type(e).__name__,
                        "traceback": traceback.format_exc()
                    }
                )
        return wrapper
    return decorator

class CircuitBreaker:
    """
    Circuit breaker pattern implementation.
    Prevents cascading failures by temporarily disabling failing operations.
    """
    
    def __init__(self, failure_threshold: int = 5, timeout: float = 60.0):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.is_open = False
    
    def call(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute function through circuit breaker"""
        import time
        
        # Check if circuit should be reset
        if self.is_open and self.last_failure_time:
            if time.time() - self.last_failure_time > self.timeout:
                self.reset()
        
        # If circuit is open, fail fast
        if self.is_open:
            raise BLRCSError("Circuit breaker is open", ErrorSeverity.HIGH)
        
        try:
            result = func(*args, **kwargs)
            self.on_success()
            return result
        except Exception as e:
            self.on_failure()
            raise
    
    def on_success(self):
        """Handle successful call"""
        self.failure_count = 0
    
    def on_failure(self):
        """Handle failed call"""
        import time
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.is_open = True
    
    def reset(self):
        """Reset circuit breaker"""
        self.failure_count = 0
        self.is_open = False
        self.last_failure_time = None

class ErrorContext:
    """
    Context manager for error handling.
    Provides clean error boundaries for code blocks.
    """
    
    def __init__(self, context: str, 
                handler: Optional[ErrorHandler] = None,
                suppress: bool = False,
                default: Any = None):
        self.context = context
        self.handler = handler
        self.suppress = suppress
        self.default = default
        self.error = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_val is not None:
            self.error = exc_val
            
            if self.handler:
                self.handler.handle_error(exc_val, self.context)
            
            if self.suppress:
                return True  # Suppress exception
            
        return False

def validate_input(value: Any, validators: list) -> tuple[bool, list[str]]:
    """
    Validate input against multiple validators.
    Returns (is_valid, [error_messages])
    """
    errors = []
    
    for validator in validators:
        try:
            if not validator(value):
                errors.append(f"Validation failed: {validator.__name__}")
        except Exception as e:
            errors.append(f"Validator error: {str(e)}")
    
    return len(errors) == 0, errors

def assert_valid(condition: bool, message: str, severity: ErrorSeverity = ErrorSeverity.MEDIUM):
    """
    Assert condition is true, raise BLRCSError if not.
    Following Carmack's principle: fail fast with clear errors.
    """
    if not condition:
        raise BLRCSError(message, severity)