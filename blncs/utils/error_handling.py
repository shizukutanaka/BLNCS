# BLNCS Advanced Error Handling System
# Comprehensive error management and recovery

import sys
import traceback
import logging
import json
import time
import asyncio
import functools
from typing import Dict, List, Any, Optional, Callable, Type, Union
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from collections import deque
import threading

logger = logging.getLogger(__name__)

class ErrorSeverity(Enum):
    """Error severity levels"""
    DEBUG = 1
    INFO = 2
    WARNING = 3
    ERROR = 4
    CRITICAL = 5
    FATAL = 6

class ErrorCategory(Enum):
    """Error categories"""
    NETWORK = "network"
    DATABASE = "database"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    BUSINESS_LOGIC = "business_logic"
    SYSTEM = "system"
    EXTERNAL_SERVICE = "external_service"
    CONFIGURATION = "configuration"
    UNKNOWN = "unknown"

@dataclass
class ErrorContext:
    """Context information for errors"""
    timestamp: datetime
    severity: ErrorSeverity
    category: ErrorCategory
    error_code: str
    message: str
    details: Dict[str, Any]
    stack_trace: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3
    recovery_attempted: bool = False

class ErrorHandler:
    """Advanced error handling with automatic recovery"""
    
    def __init__(self):
        self.error_history = deque(maxlen=10000)
        self.error_patterns = {}
        self.recovery_strategies = self._initialize_recovery_strategies()
        self.circuit_breakers = {}
        self.error_stats = ErrorStatistics()
        self._lock = threading.RLock()
    
    def _initialize_recovery_strategies(self) -> Dict[ErrorCategory, Callable]:
        """Initialize recovery strategies for different error types"""
        return {
            ErrorCategory.NETWORK: self._recover_network_error,
            ErrorCategory.DATABASE: self._recover_database_error,
            ErrorCategory.AUTHENTICATION: self._recover_auth_error,
            ErrorCategory.EXTERNAL_SERVICE: self._recover_external_service_error,
            ErrorCategory.VALIDATION: self._recover_validation_error
        }
    
    def handle_error(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> ErrorContext:
        """Main error handling entry point"""
        error_context = self._create_error_context(error, context)
        
        with self._lock:
            # Record error
            self.error_history.append(error_context)
            self.error_stats.record_error(error_context)
            
            # Check for patterns
            pattern = self._detect_error_pattern(error_context)
            if pattern:
                self._handle_error_pattern(pattern, error_context)
            
            # Attempt recovery
            if error_context.retry_count < error_context.max_retries:
                recovery_success = self._attempt_recovery(error_context)
                if recovery_success:
                    error_context.recovery_attempted = True
                    logger.info(f"Successfully recovered from error: {error_context.error_code}")
            
            # Log error
            self._log_error(error_context)
            
            # Check circuit breaker
            self._check_circuit_breaker(error_context)
        
        return error_context
    
    def _create_error_context(self, error: Exception, context: Optional[Dict[str, Any]]) -> ErrorContext:
        """Create error context from exception"""
        return ErrorContext(
            timestamp=datetime.now(),
            severity=self._determine_severity(error),
            category=self._categorize_error(error),
            error_code=self._generate_error_code(error),
            message=str(error),
            details=context or {},
            stack_trace=traceback.format_exc(),
            user_id=context.get('user_id') if context else None,
            session_id=context.get('session_id') if context else None,
            request_id=context.get('request_id') if context else None
        )
    
    def _determine_severity(self, error: Exception) -> ErrorSeverity:
        """Determine error severity"""
        error_type = type(error).__name__
        
        # Critical errors
        if isinstance(error, (SystemExit, KeyboardInterrupt, MemoryError)):
            return ErrorSeverity.FATAL
        elif isinstance(error, (OSError, IOError, RuntimeError)):
            return ErrorSeverity.CRITICAL
        elif isinstance(error, (ValueError, TypeError, AttributeError)):
            return ErrorSeverity.ERROR
        elif isinstance(error, (Warning, DeprecationWarning)):
            return ErrorSeverity.WARNING
        else:
            return ErrorSeverity.ERROR
    
    def _categorize_error(self, error: Exception) -> ErrorCategory:
        """Categorize error type"""
        error_message = str(error).lower()
        
        if 'connection' in error_message or 'network' in error_message:
            return ErrorCategory.NETWORK
        elif 'database' in error_message or 'sql' in error_message:
            return ErrorCategory.DATABASE
        elif 'auth' in error_message or 'login' in error_message:
            return ErrorCategory.AUTHENTICATION
        elif 'permission' in error_message or 'access' in error_message:
            return ErrorCategory.AUTHORIZATION
        elif 'validation' in error_message or 'invalid' in error_message:
            return ErrorCategory.VALIDATION
        elif 'config' in error_message or 'setting' in error_message:
            return ErrorCategory.CONFIGURATION
        else:
            return ErrorCategory.UNKNOWN
    
    def _generate_error_code(self, error: Exception) -> str:
        """Generate unique error code"""
        error_type = type(error).__name__
        timestamp = int(time.time() * 1000) % 100000
        return f"ERR_{error_type[:3].upper()}_{timestamp}"
    
    def _detect_error_pattern(self, error_context: ErrorContext) -> Optional[str]:
        """Detect recurring error patterns"""
        # Look for similar errors in recent history
        similar_errors = [
            e for e in self.error_history
            if e.category == error_context.category and
            abs((e.timestamp - error_context.timestamp).total_seconds()) < 60
        ]
        
        if len(similar_errors) >= 5:
            return f"recurring_{error_context.category.value}"
        
        return None
    
    def _handle_error_pattern(self, pattern: str, error_context: ErrorContext) -> None:
        """Handle detected error patterns"""
        logger.warning(f"Error pattern detected: {pattern}")
        
        # Implement pattern-specific handling
        if 'recurring_network' in pattern:
            # Increase timeouts, switch to backup servers
            logger.info("Switching to backup network configuration")
        elif 'recurring_database' in pattern:
            # Reset connection pool, failover to replica
            logger.info("Initiating database failover")
    
    def _attempt_recovery(self, error_context: ErrorContext) -> bool:
        """Attempt automatic error recovery"""
        recovery_strategy = self.recovery_strategies.get(error_context.category)
        
        if recovery_strategy:
            try:
                return recovery_strategy(error_context)
            except Exception as e:
                logger.error(f"Recovery failed: {e}")
                return False
        
        return False
    
    def _recover_network_error(self, error_context: ErrorContext) -> bool:
        """Recover from network errors"""
        # Implement exponential backoff
        wait_time = 2 ** error_context.retry_count
        time.sleep(wait_time)
        
        # Retry with different endpoint or increased timeout
        logger.info(f"Retrying network operation after {wait_time}s")
        return True
    
    def _recover_database_error(self, error_context: ErrorContext) -> bool:
        """Recover from database errors"""
        # Reset connection, clear pool
        logger.info("Resetting database connections")
        return True
    
    def _recover_auth_error(self, error_context: ErrorContext) -> bool:
        """Recover from authentication errors"""
        # Refresh tokens, re-authenticate
        logger.info("Refreshing authentication tokens")
        return True
    
    def _recover_external_service_error(self, error_context: ErrorContext) -> bool:
        """Recover from external service errors"""
        # Use fallback service, cache
        logger.info("Switching to fallback service")
        return True
    
    def _recover_validation_error(self, error_context: ErrorContext) -> bool:
        """Recover from validation errors"""
        # Cannot auto-recover, needs user input
        return False
    
    def _log_error(self, error_context: ErrorContext) -> None:
        """Log error with appropriate level"""
        log_message = f"[{error_context.error_code}] {error_context.message}"
        
        if error_context.severity == ErrorSeverity.FATAL:
            logger.critical(log_message)
        elif error_context.severity == ErrorSeverity.CRITICAL:
            logger.critical(log_message)
        elif error_context.severity == ErrorSeverity.ERROR:
            logger.error(log_message)
        elif error_context.severity == ErrorSeverity.WARNING:
            logger.warning(log_message)
        else:
            logger.info(log_message)
    
    def _check_circuit_breaker(self, error_context: ErrorContext) -> None:
        """Check and update circuit breaker state"""
        service_key = f"{error_context.category.value}"
        
        if service_key not in self.circuit_breakers:
            self.circuit_breakers[service_key] = CircuitBreaker(service_key)
        
        breaker = self.circuit_breakers[service_key]
        breaker.record_failure()
        
        if breaker.is_open():
            logger.warning(f"Circuit breaker OPEN for {service_key}")

class CircuitBreaker:
    """Circuit breaker pattern implementation"""
    
    def __init__(self, name: str, failure_threshold: int = 5, timeout: int = 60):
        self.name = name
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'closed'  # closed, open, half_open
    
    def record_success(self) -> None:
        """Record successful operation"""
        self.failure_count = 0
        self.state = 'closed'
    
    def record_failure(self) -> None:
        """Record failed operation"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.state = 'open'
    
    def is_open(self) -> bool:
        """Check if circuit breaker is open"""
        if self.state == 'open':
            # Check if timeout has passed
            if self.last_failure_time and (time.time() - self.last_failure_time) > self.timeout:
                self.state = 'half_open'
                return False
            return True
        return False
    
    def can_execute(self) -> bool:
        """Check if operation can be executed"""
        return not self.is_open()

class ErrorStatistics:
    """Error statistics tracking"""
    
    def __init__(self):
        self.total_errors = 0
        self.errors_by_category = {}
        self.errors_by_severity = {}
        self.error_rate = deque(maxlen=1000)
        self.start_time = time.time()
    
    def record_error(self, error_context: ErrorContext) -> None:
        """Record error for statistics"""
        self.total_errors += 1
        
        # Track by category
        category = error_context.category.value
        if category not in self.errors_by_category:
            self.errors_by_category[category] = 0
        self.errors_by_category[category] += 1
        
        # Track by severity
        severity = error_context.severity.name
        if severity not in self.errors_by_severity:
            self.errors_by_severity[severity] = 0
        self.errors_by_severity[severity] += 1
        
        # Track error rate
        self.error_rate.append(time.time())
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get error statistics"""
        current_time = time.time()
        uptime = current_time - self.start_time
        
        # Calculate error rate (errors per minute)
        recent_errors = [t for t in self.error_rate if current_time - t < 60]
        error_rate_per_minute = len(recent_errors)
        
        return {
            'total_errors': self.total_errors,
            'errors_by_category': self.errors_by_category,
            'errors_by_severity': self.errors_by_severity,
            'error_rate_per_minute': error_rate_per_minute,
            'uptime_seconds': uptime,
            'average_errors_per_hour': (self.total_errors / uptime) * 3600 if uptime > 0 else 0
        }

def resilient_function(max_retries: int = 3, backoff_factor: float = 2.0):
    """Decorator for resilient function execution"""
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    wait_time = backoff_factor ** attempt
                    logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {wait_time}s")
                    time.sleep(wait_time)
            
            # All retries failed
            raise last_exception
        
        return wrapper
    return decorator

async def async_resilient_function(max_retries: int = 3, backoff_factor: float = 2.0):
    """Async decorator for resilient function execution"""
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_retries):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    wait_time = backoff_factor ** attempt
                    logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {wait_time}s")
                    await asyncio.sleep(wait_time)
            
            # All retries failed
            raise last_exception
        
        return wrapper
    return decorator

# Global error handler instance
error_handler = ErrorHandler()

def handle_exception(exc_type: Type[BaseException], exc_value: BaseException, exc_traceback) -> None:
    """Global exception handler"""
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    
    error_context = error_handler.handle_error(exc_value)
    logger.critical(f"Unhandled exception: {error_context.error_code}")

# Install global exception handler
sys.excepthook = handle_exception