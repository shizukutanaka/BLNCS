"""
Lightweight Error Recovery System for BLNCS
Simple and practical error recovery mechanisms.
"""

import logging
import traceback
import time
import threading
from typing import Any, Callable, Optional, Dict, List
from dataclasses import dataclass
from enum import Enum
from contextlib import contextmanager

logger = logging.getLogger(__name__)

class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = 1       # Non-critical, can continue
    MEDIUM = 2    # Important, may affect functionality
    HIGH = 3      # Critical, immediate attention needed
    FATAL = 4     # System cannot continue

@dataclass
class ErrorContext:
    """Error context information"""
    component: str
    operation: str
    error: Exception
    severity: ErrorSeverity
    timestamp: float
    retry_count: int = 0

class ErrorRecoveryManager:
    """Simple error recovery manager"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.error_history: List[ErrorContext] = []
        self.recovery_strategies: Dict[str, Callable] = {}
        self.lock = threading.Lock()
        
        # Default recovery strategies
        self._setup_default_strategies()
    
    def _setup_default_strategies(self):
        """Setup default error recovery strategies"""
        self.recovery_strategies = {
            'connection_error': self._handle_connection_error,
            'database_error': self._handle_database_error,
            'config_error': self._handle_config_error,
            'permission_error': self._handle_permission_error,
            'resource_error': self._handle_resource_error,
        }
    
    def register_strategy(self, error_type: str, strategy: Callable):
        """Register custom error recovery strategy"""
        self.recovery_strategies[error_type] = strategy
        self.logger.info(f"Registered recovery strategy for {error_type}")
    
    def handle_error(self, 
                    component: str, 
                    operation: str, 
                    error: Exception, 
                    severity: ErrorSeverity = ErrorSeverity.MEDIUM) -> bool:
        """
        Handle error with appropriate recovery strategy
        Returns True if recovery was successful, False otherwise
        """
        context = ErrorContext(
            component=component,
            operation=operation,
            error=error,
            severity=severity,
            timestamp=time.time()
        )
        
        with self.lock:
            self.error_history.append(context)
            # Keep only last 100 errors
            if len(self.error_history) > 100:
                self.error_history = self.error_history[-50:]
        
        self.logger.error(f"Error in {component}.{operation}: {error}")
        
        # Attempt recovery based on error type
        error_type = self._classify_error(error)
        if error_type in self.recovery_strategies:
            try:
                return self.recovery_strategies[error_type](context)
            except Exception as recovery_error:
                self.logger.error(f"Recovery strategy failed: {recovery_error}")
        
        return False
    
    def _classify_error(self, error: Exception) -> str:
        """Classify error type for recovery strategy selection"""
        error_name = type(error).__name__.lower()
        
        if 'connection' in error_name or 'timeout' in error_name:
            return 'connection_error'
        elif 'database' in error_name or 'sqlite' in error_name:
            return 'database_error'
        elif 'config' in error_name or 'json' in error_name:
            return 'config_error'
        elif 'permission' in error_name or 'access' in error_name:
            return 'permission_error'
        elif 'memory' in error_name or 'resource' in error_name:
            return 'resource_error'
        
        return 'unknown'
    
    def _handle_connection_error(self, context: ErrorContext) -> bool:
        """Handle connection-related errors"""
        self.logger.info(f"Attempting connection error recovery for {context.component}")
        
        # Wait before retry
        time.sleep(min(2.0 * (context.retry_count + 1), 10.0))
        
        # Mark for retry if not too many attempts
        if context.retry_count < 3:
            context.retry_count += 1
            return True
        
        return False
    
    def _handle_database_error(self, context: ErrorContext) -> bool:
        """Handle database-related errors"""
        self.logger.info(f"Attempting database error recovery for {context.component}")
        
        try:
            # Try to reconnect to database
            from .database import get_database
            db = get_database()
            db.execute("SELECT 1")  # Test query
            return True
        except Exception as e:
            self.logger.error(f"Database recovery failed: {e}")
            return False
    
    def _handle_config_error(self, context: ErrorContext) -> bool:
        """Handle configuration-related errors"""
        self.logger.info(f"Attempting config error recovery for {context.component}")
        
        try:
            # Try to reload configuration
            from .config_manager import get_config_manager
            config = get_config_manager()
            config.reload()
            return True
        except Exception as e:
            self.logger.error(f"Config recovery failed: {e}")
            return False
    
    def _handle_permission_error(self, context: ErrorContext) -> bool:
        """Handle permission-related errors"""
        self.logger.warning(f"Permission error in {context.component}: {context.error}")
        # Permission errors typically require manual intervention
        return False
    
    def _handle_resource_error(self, context: ErrorContext) -> bool:
        """Handle resource-related errors"""
        self.logger.info(f"Attempting resource error recovery for {context.component}")
        
        # Try to free up some resources
        import gc
        gc.collect()
        
        time.sleep(1.0)  # Give system time to recover
        return True
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of recent errors"""
        with self.lock:
            if not self.error_history:
                return {'total_errors': 0, 'recent_errors': []}
            
            recent_errors = self.error_history[-10:]  # Last 10 errors
            error_counts = {}
            
            for error_context in self.error_history:
                component = error_context.component
                error_counts[component] = error_counts.get(component, 0) + 1
            
            return {
                'total_errors': len(self.error_history),
                'error_counts_by_component': error_counts,
                'recent_errors': [
                    {
                        'component': ctx.component,
                        'operation': ctx.operation,
                        'error': str(ctx.error),
                        'severity': ctx.severity.name,
                        'timestamp': ctx.timestamp
                    }
                    for ctx in recent_errors
                ]
            }

@contextmanager
def error_recovery_context(component: str, operation: str, severity: ErrorSeverity = ErrorSeverity.MEDIUM):
    """Context manager for automatic error recovery"""
    try:
        yield
    except Exception as e:
        recovery_manager = get_error_recovery_manager()
        if recovery_manager.handle_error(component, operation, e, severity):
            # If recovery was successful, log but don't re-raise
            logger.info(f"Recovered from error in {component}.{operation}")
        else:
            # If recovery failed, re-raise the original exception
            raise

def safe_execute(func: Callable, component: str, operation: str, 
                default_return: Any = None, severity: ErrorSeverity = ErrorSeverity.MEDIUM) -> Any:
    """Safely execute function with error recovery"""
    try:
        return func()
    except Exception as e:
        recovery_manager = get_error_recovery_manager()
        if recovery_manager.handle_error(component, operation, e, severity):
            # Try once more after recovery
            try:
                return func()
            except Exception:
                logger.error(f"Function failed even after recovery: {component}.{operation}")
                return default_return
        else:
            logger.error(f"Recovery failed for {component}.{operation}")
            return default_return

# Create singleton instance
_recovery_manager_instance = None
_recovery_lock = threading.Lock()

def get_error_recovery_manager() -> ErrorRecoveryManager:
    """Get or create error recovery manager instance"""
    global _recovery_manager_instance
    if _recovery_manager_instance is None:
        with _recovery_lock:
            if _recovery_manager_instance is None:
                _recovery_manager_instance = ErrorRecoveryManager()
    return _recovery_manager_instance

__all__ = [
    'ErrorRecoveryManager', 'ErrorSeverity', 'ErrorContext',
    'error_recovery_context', 'safe_execute', 'get_error_recovery_manager'
]