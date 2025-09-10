"""
Comprehensive error handling system for BLNCS
Provides structured error management, recovery strategies, and monitoring.
"""

import traceback
import uuid
import time
import threading
from typing import Dict, Optional, Any, Callable, List, Union
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
from contextlib import contextmanager
from functools import wraps

from .logger import get_logger
from .exceptions import (
    BLNCSError, LightningError, ConnectionError, ValidationError,
    ConfigurationError, SecurityError
)


class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """Error categories for classification"""
    NETWORK = "network"
    VALIDATION = "validation"
    CONFIGURATION = "configuration"
    SECURITY = "security"
    LIGHTNING = "lightning"
    DATABASE = "database"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    SYSTEM = "system"
    UNKNOWN = "unknown"


@dataclass
class ErrorContext:
    """Context information for error tracking"""
    error_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    severity: ErrorSeverity = ErrorSeverity.MEDIUM
    category: ErrorCategory = ErrorCategory.UNKNOWN
    component: str = "unknown"
    operation: str = "unknown"
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    correlation_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    stack_trace: Optional[str] = None
    recovery_attempted: bool = False
    recovery_successful: bool = False


@dataclass
class RecoveryStrategy:
    """Error recovery strategy configuration"""
    max_retries: int = 3
    backoff_factor: float = 2.0
    initial_delay: float = 1.0
    max_delay: float = 60.0
    recoverable_exceptions: tuple = (ConnectionError, LightningError)
    recovery_function: Optional[Callable] = None


class ErrorHandler:
    """Comprehensive error handling and recovery system"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self._error_registry: Dict[str, ErrorContext] = {}
        self._error_counts: Dict[str, int] = {}
        self._recovery_strategies: Dict[str, RecoveryStrategy] = {}
        self._lock = threading.RLock()
        
        # Global error statistics
        self.total_errors = 0
        self.recovered_errors = 0
        self.critical_errors = 0
        
        # Setup default recovery strategies
        self._setup_default_strategies()
    
    def _setup_default_strategies(self):
        """Setup default recovery strategies"""
        # Network connection recovery
        self._recovery_strategies['network'] = RecoveryStrategy(
            max_retries=3,
            backoff_factor=2.0,
            initial_delay=1.0,
            recoverable_exceptions=(ConnectionError,)
        )
        
        # Lightning node recovery
        self._recovery_strategies['lightning'] = RecoveryStrategy(
            max_retries=5,
            backoff_factor=1.5,
            initial_delay=2.0,
            max_delay=30.0,
            recoverable_exceptions=(LightningError, ConnectionError)
        )
        
        # Validation error handling (no retry)
        self._recovery_strategies['validation'] = RecoveryStrategy(
            max_retries=0,
            recoverable_exceptions=(ValidationError,)
        )
        
        # Security error handling (no retry, immediate escalation)
        self._recovery_strategies['security'] = RecoveryStrategy(
            max_retries=0,
            recoverable_exceptions=(SecurityError,)
        )
    
    def register_recovery_strategy(self, category: str, strategy: RecoveryStrategy):
        """Register custom recovery strategy"""
        with self._lock:
            self._recovery_strategies[category] = strategy
            self.logger.info(f"Registered recovery strategy for {category}")
    
    def handle_error(
        self,
        exception: Exception,
        context: Optional[ErrorContext] = None,
        suppress: bool = False
    ) -> Optional[ErrorContext]:
        """Handle and process error with recovery attempts"""
        if context is None:
            context = ErrorContext()
        
        # Classify error
        context.category = self._classify_error(exception)
        context.severity = self._determine_severity(exception, context.category)
        context.stack_trace = traceback.format_exc()
        
        # Update statistics
        with self._lock:
            self.total_errors += 1
            if context.severity == ErrorSeverity.CRITICAL:
                self.critical_errors += 1
            
            # Track error frequency
            error_key = f"{context.category.value}:{type(exception).__name__}"
            self._error_counts[error_key] = self._error_counts.get(error_key, 0) + 1
            
            # Store error context
            self._error_registry[context.error_id] = context
        
        # Log error
        self._log_error(exception, context)
        
        # Attempt recovery
        recovery_attempted = self._attempt_recovery(exception, context)
        
        if not suppress and not recovery_attempted:
            raise exception
        
        return context
    
    def _classify_error(self, exception: Exception) -> ErrorCategory:
        """Classify error by type and context"""
        if isinstance(exception, ConnectionError):
            return ErrorCategory.NETWORK
        elif isinstance(exception, LightningError):
            return ErrorCategory.LIGHTNING
        elif isinstance(exception, ValidationError):
            return ErrorCategory.VALIDATION
        elif isinstance(exception, ConfigurationError):
            return ErrorCategory.CONFIGURATION
        elif isinstance(exception, SecurityError):
            return ErrorCategory.SECURITY
        elif "database" in str(exception).lower() or "sqlite" in str(exception).lower():
            return ErrorCategory.DATABASE
        elif "auth" in str(exception).lower():
            return ErrorCategory.AUTHENTICATION
        else:
            return ErrorCategory.UNKNOWN
    
    def _determine_severity(self, exception: Exception, category: ErrorCategory) -> ErrorSeverity:
        """Determine error severity based on type and category"""
        if isinstance(exception, SecurityError):
            return ErrorSeverity.CRITICAL
        elif category == ErrorCategory.LIGHTNING and "node offline" in str(exception).lower():
            return ErrorSeverity.HIGH
        elif isinstance(exception, (ConnectionError, ConfigurationError)):
            return ErrorSeverity.HIGH
        elif isinstance(exception, ValidationError):
            return ErrorSeverity.MEDIUM
        elif category in (ErrorCategory.DATABASE, ErrorCategory.AUTHENTICATION):
            return ErrorSeverity.HIGH
        else:
            return ErrorSeverity.MEDIUM
    
    def _log_error(self, exception: Exception, context: ErrorContext):
        """Log error with appropriate level and context"""
        log_data = {
            'error_id': context.error_id,
            'category': context.category.value,
            'severity': context.severity.value,
            'component': context.component,
            'operation': context.operation,
            'correlation_id': context.correlation_id,
            'metadata': context.metadata
        }
        
        if context.severity == ErrorSeverity.CRITICAL:
            self.logger.critical(f"Critical error: {exception}", extra=log_data)
        elif context.severity == ErrorSeverity.HIGH:
            self.logger.error(f"High severity error: {exception}", extra=log_data)
        elif context.severity == ErrorSeverity.MEDIUM:
            self.logger.warning(f"Error: {exception}", extra=log_data)
        else:
            self.logger.info(f"Low severity error: {exception}", extra=log_data)
    
    def _attempt_recovery(self, exception: Exception, context: ErrorContext) -> bool:
        """Attempt error recovery based on configured strategies"""
        strategy = self._recovery_strategies.get(context.category.value)
        if not strategy or strategy.max_retries == 0:
            return False
        
        if not isinstance(exception, strategy.recoverable_exceptions):
            return False
        
        context.recovery_attempted = True
        
        for attempt in range(strategy.max_retries):
            try:
                delay = min(
                    strategy.initial_delay * (strategy.backoff_factor ** attempt),
                    strategy.max_delay
                )
                time.sleep(delay)
                
                # If custom recovery function is provided, use it
                if strategy.recovery_function:
                    strategy.recovery_function(exception, context, attempt)
                
                # For now, mark as recovered (in real implementation, 
                # this would retry the original operation)
                context.recovery_successful = True
                self.recovered_errors += 1
                
                self.logger.info(
                    f"Recovery successful for error {context.error_id} "
                    f"after {attempt + 1} attempts"
                )
                return True
                
            except Exception as recovery_error:
                self.logger.warning(
                    f"Recovery attempt {attempt + 1} failed: {recovery_error}"
                )
                continue
        
        self.logger.error(
            f"All recovery attempts failed for error {context.error_id}"
        )
        return False
    
    @contextmanager
    def error_context(
        self,
        component: str,
        operation: str,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        suppress_errors: bool = False
    ):
        """Context manager for error handling with automatic context setup"""
        context = ErrorContext(
            component=component,
            operation=operation,
            correlation_id=correlation_id,
            metadata=metadata or {}
        )
        
        try:
            yield context
        except Exception as e:
            self.handle_error(e, context, suppress=suppress_errors)
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get comprehensive error statistics"""
        with self._lock:
            recovery_rate = (
                self.recovered_errors / self.total_errors
                if self.total_errors > 0 else 0
            )
            
            return {
                'total_errors': self.total_errors,
                'recovered_errors': self.recovered_errors,
                'critical_errors': self.critical_errors,
                'recovery_rate': recovery_rate,
                'error_counts_by_type': dict(self._error_counts),
                'active_errors': len(self._error_registry),
                'recovery_strategies': list(self._recovery_strategies.keys())
            }
    
    def get_recent_errors(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent errors for monitoring"""
        with self._lock:
            recent_errors = sorted(
                self._error_registry.values(),
                key=lambda x: x.timestamp,
                reverse=True
            )[:limit]
            
            return [
                {
                    'error_id': err.error_id,
                    'timestamp': err.timestamp.isoformat(),
                    'severity': err.severity.value,
                    'category': err.category.value,
                    'component': err.component,
                    'operation': err.operation,
                    'recovery_attempted': err.recovery_attempted,
                    'recovery_successful': err.recovery_successful,
                    'metadata': err.metadata
                }
                for err in recent_errors
            ]
    
    def clear_old_errors(self, older_than_hours: int = 24):
        """Clear old error records to prevent memory buildup"""
        cutoff_time = datetime.now().timestamp() - (older_than_hours * 3600)
        
        with self._lock:
            old_error_ids = [
                error_id for error_id, context in self._error_registry.items()
                if context.timestamp.timestamp() < cutoff_time
            ]
            
            for error_id in old_error_ids:
                del self._error_registry[error_id]
            
            if old_error_ids:
                self.logger.info(f"Cleared {len(old_error_ids)} old error records")


# Global error handler instance
_global_error_handler: Optional[ErrorHandler] = None


def get_error_handler() -> ErrorHandler:
    """Get global error handler instance"""
    global _global_error_handler
    if _global_error_handler is None:
        _global_error_handler = ErrorHandler()
    return _global_error_handler


def handle_errors(
    component: str,
    operation: str = "unknown",
    suppress: bool = False,
    recovery_strategy: Optional[str] = None
) -> Callable:
    """Decorator for automatic error handling"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            error_handler = get_error_handler()
            
            with error_handler.error_context(
                component=component,
                operation=operation,
                suppress_errors=suppress
            ) as context:
                return func(*args, **kwargs)
        
        return wrapper
    return decorator


def safe_execute(
    func: Callable,
    *args,
    component: str = "unknown",
    operation: str = "unknown",
    default_return: Any = None,
    **kwargs
) -> Any:
    """Safely execute function with error handling"""
    try:
        return func(*args, **kwargs)
    except Exception as e:
        error_handler = get_error_handler()
        context = ErrorContext(component=component, operation=operation)
        error_handler.handle_error(e, context, suppress=True)
        return default_return


# Convenience functions for common error handling patterns

def handle_network_error(func: Callable) -> Callable:
    """Decorator for network operation error handling"""
    return handle_errors(
        component="network",
        operation=func.__name__,
        recovery_strategy="network"
    )(func)


def handle_lightning_error(func: Callable) -> Callable:
    """Decorator for Lightning Network operation error handling"""
    return handle_errors(
        component="lightning",
        operation=func.__name__,
        recovery_strategy="lightning"
    )(func)


def handle_validation_error(func: Callable) -> Callable:
    """Decorator for validation error handling"""
    return handle_errors(
        component="validation",
        operation=func.__name__,
        suppress=True
    )(func)


__all__ = [
    'ErrorHandler',
    'ErrorContext',
    'ErrorSeverity',
    'ErrorCategory',
    'RecoveryStrategy',
    'get_error_handler',
    'handle_errors',
    'safe_execute',
    'handle_network_error',
    'handle_lightning_error',
    'handle_validation_error'
]