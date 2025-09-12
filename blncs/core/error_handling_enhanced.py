#!/usr/bin/env python3
"""
Enhanced Error Handling and Logging System for BLNCS
Advanced error management with comprehensive logging, metrics, and recovery
"""

import logging
import logging.handlers
import sys
import os
import traceback
import functools
import threading
import time
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union, Type
from dataclasses import dataclass, asdict
from enum import Enum
import inspect


class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """Error categories for classification"""
    NETWORK = "network"
    LIGHTNING = "lightning"
    DATABASE = "database"
    CONFIG = "configuration"
    AUTH = "authentication"
    VALIDATION = "validation"
    SYSTEM = "system"
    GUI = "gui"
    API = "api"
    UNKNOWN = "unknown"


@dataclass
class ErrorInfo:
    """Comprehensive error information"""
    error_id: str
    timestamp: datetime
    severity: ErrorSeverity
    category: ErrorCategory
    message: str
    exception_type: str
    traceback: str
    function_name: str
    file_name: str
    line_number: int
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    context: Optional[Dict[str, Any]] = None
    recoverable: bool = True
    recovery_attempts: int = 0
    max_recovery_attempts: int = 3


class ErrorMetrics:
    """Error metrics collection"""
    
    def __init__(self):
        self._lock = threading.RLock()
        self._error_counts = {}
        self._error_history = []
        self._recovery_stats = {}
    
    def record_error(self, error_info: ErrorInfo):
        """Record error occurrence"""
        with self._lock:
            # Count by category and severity
            key = f"{error_info.category.value}:{error_info.severity.value}"
            self._error_counts[key] = self._error_counts.get(key, 0) + 1
            
            # Add to history (keep last 1000)
            self._error_history.append(error_info)
            if len(self._error_history) > 1000:
                self._error_history = self._error_history[-1000:]
            
            # Track recovery attempts
            if error_info.recovery_attempts > 0:
                recovery_key = f"{error_info.category.value}:recovery"
                if recovery_key not in self._recovery_stats:
                    self._recovery_stats[recovery_key] = {'attempts': 0, 'successes': 0}
                self._recovery_stats[recovery_key]['attempts'] += error_info.recovery_attempts
    
    def record_recovery(self, category: ErrorCategory):
        """Record successful error recovery"""
        with self._lock:
            recovery_key = f"{category.value}:recovery"
            if recovery_key in self._recovery_stats:
                self._recovery_stats[recovery_key]['successes'] += 1
    
    def get_error_stats(self) -> Dict[str, Any]:
        """Get error statistics"""
        with self._lock:
            return {
                'error_counts': self._error_counts.copy(),
                'total_errors': len(self._error_history),
                'recovery_stats': self._recovery_stats.copy(),
                'recent_errors': len([e for e in self._error_history 
                                    if (datetime.now(timezone.utc) - e.timestamp).seconds < 3600])
            }
    
    def get_error_history(self, limit: int = 100) -> List[ErrorInfo]:
        """Get recent error history"""
        with self._lock:
            return self._error_history[-limit:]


class ContextualFormatter(logging.Formatter):
    """Enhanced formatter with contextual information"""
    
    def __init__(self, include_context: bool = True):
        super().__init__()
        self.include_context = include_context
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with enhanced context"""
        # Base formatting
        timestamp = datetime.fromtimestamp(record.created, tz=timezone.utc)
        
        # Build format components
        components = [
            f"{timestamp.isoformat()}",
            f"[{record.levelname}]",
            f"{record.name}",
        ]
        
        # Add thread info for multi-threaded operations
        if hasattr(record, 'thread_name') or threading.current_thread().name != 'MainThread':
            thread_name = getattr(record, 'thread_name', threading.current_thread().name)
            components.append(f"({thread_name})")
        
        # Add function context
        if hasattr(record, 'funcName') and record.funcName:
            components.append(f"{record.funcName}()")
        
        # Main message
        components.append(f": {record.getMessage()}")
        
        # Add context information
        if self.include_context and hasattr(record, 'context'):
            context_str = json.dumps(record.context, separators=(',', ':'))
            components.append(f" | Context: {context_str}")
        
        # Add error details for exceptions
        if record.exc_info:
            components.append("\n" + self.formatException(record.exc_info))
        
        return " ".join(components)


class EnhancedLogger:
    """Enhanced logging system with structured logging and error tracking"""
    
    def __init__(self, name: str = "BLNCS", log_dir: str = "logs"):
        self.name = name
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Error tracking
        self.error_metrics = ErrorMetrics()
        self._error_handlers: Dict[ErrorCategory, List[Callable]] = {}
        self._recovery_strategies: Dict[ErrorCategory, Callable] = {}
        
        # Setup loggers
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        # Remove default handlers
        self.logger.handlers.clear()
        
        # Setup handlers
        self._setup_handlers()
        
        # Session tracking
        self._session_id = self._generate_session_id()
        self._user_id = None
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        return f"session_{int(time.time())}_{os.getpid()}"
    
    def _setup_handlers(self):
        """Setup logging handlers"""
        formatter = ContextualFormatter()
        
        # Console handler with color support
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(self._get_console_formatter())
        self.logger.addHandler(console_handler)
        
        # File handler for all logs
        all_log_file = self.log_dir / "blncs.log"
        file_handler = logging.handlers.RotatingFileHandler(
            all_log_file, maxBytes=10*1024*1024, backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Error-specific handler
        error_log_file = self.log_dir / "errors.log"
        error_handler = logging.handlers.RotatingFileHandler(
            error_log_file, maxBytes=5*1024*1024, backupCount=10
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(formatter)
        self.logger.addHandler(error_handler)
        
        # JSON structured log handler
        json_log_file = self.log_dir / "structured.jsonl"
        json_handler = logging.handlers.RotatingFileHandler(
            json_log_file, maxBytes=20*1024*1024, backupCount=3
        )
        json_handler.setLevel(logging.INFO)
        json_handler.setFormatter(self._get_json_formatter())
        self.logger.addHandler(json_handler)
    
    def _get_console_formatter(self) -> logging.Formatter:
        """Get console formatter with colors"""
        class ColorFormatter(logging.Formatter):
            COLORS = {
                'DEBUG': '\033[36m',      # Cyan
                'INFO': '\033[32m',       # Green
                'WARNING': '\033[33m',    # Yellow
                'ERROR': '\033[31m',      # Red
                'CRITICAL': '\033[35m',   # Magenta
                'ENDC': '\033[0m'         # End color
            }
            
            def format(self, record):
                colored_levelname = f"{self.COLORS.get(record.levelname, '')}{record.levelname}{self.COLORS['ENDC']}"
                record.levelname = colored_levelname
                return super().format(record)
        
        return ColorFormatter(
            fmt='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%H:%M:%S'
        )
    
    def _get_json_formatter(self) -> logging.Formatter:
        """Get JSON formatter for structured logging"""
        class JSONFormatter(logging.Formatter):
            def format(self, record):
                log_obj = {
                    'timestamp': datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
                    'level': record.levelname,
                    'logger': record.name,
                    'message': record.getMessage(),
                    'module': record.module,
                    'function': record.funcName,
                    'line': record.lineno
                }
                
                if hasattr(record, 'context'):
                    log_obj['context'] = record.context
                
                if record.exc_info:
                    log_obj['exception'] = {
                        'type': record.exc_info[0].__name__,
                        'message': str(record.exc_info[1]),
                        'traceback': traceback.format_exception(*record.exc_info)
                    }
                
                return json.dumps(log_obj, separators=(',', ':'))
        
        return JSONFormatter()
    
    def set_user_context(self, user_id: str):
        """Set user context for logging"""
        self._user_id = user_id
    
    def log_with_context(self, level: int, message: str, context: Optional[Dict] = None, **kwargs):
        """Log message with contextual information"""
        extra = {
            'context': context or {},
            'session_id': self._session_id,
            'user_id': self._user_id,
            **kwargs
        }
        self.logger.log(level, message, extra=extra)
    
    def debug(self, message: str, context: Optional[Dict] = None, **kwargs):
        """Log debug message"""
        self.log_with_context(logging.DEBUG, message, context, **kwargs)
    
    def info(self, message: str, context: Optional[Dict] = None, **kwargs):
        """Log info message"""
        self.log_with_context(logging.INFO, message, context, **kwargs)
    
    def warning(self, message: str, context: Optional[Dict] = None, **kwargs):
        """Log warning message"""
        self.log_with_context(logging.WARNING, message, context, **kwargs)
    
    def error(self, message: str, context: Optional[Dict] = None, **kwargs):
        """Log error message"""
        self.log_with_context(logging.ERROR, message, context, **kwargs)
    
    def critical(self, message: str, context: Optional[Dict] = None, **kwargs):
        """Log critical message"""
        self.log_with_context(logging.CRITICAL, message, context, **kwargs)
    
    def log_error(self, 
                  exception: Exception,
                  severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                  category: ErrorCategory = ErrorCategory.UNKNOWN,
                  context: Optional[Dict] = None,
                  recoverable: bool = True) -> ErrorInfo:
        """
        Log detailed error information
        
        Args:
            exception: Exception instance
            severity: Error severity
            category: Error category
            context: Additional context
            recoverable: Whether error is recoverable
            
        Returns:
            ErrorInfo object
        """
        # Get caller information
        frame = inspect.currentframe().f_back
        caller_info = inspect.getframeinfo(frame)
        
        # Create error info
        error_info = ErrorInfo(
            error_id=self._generate_error_id(),
            timestamp=datetime.now(timezone.utc),
            severity=severity,
            category=category,
            message=str(exception),
            exception_type=type(exception).__name__,
            traceback=traceback.format_exc(),
            function_name=caller_info.function,
            file_name=caller_info.filename,
            line_number=caller_info.lineno,
            user_id=self._user_id,
            session_id=self._session_id,
            context=context,
            recoverable=recoverable
        )
        
        # Record metrics
        self.error_metrics.record_error(error_info)
        
        # Log error
        self.log_with_context(
            logging.ERROR,
            f"[{error_info.error_id}] {error_info.exception_type}: {error_info.message}",
            context={
                'error_id': error_info.error_id,
                'severity': severity.value,
                'category': category.value,
                'recoverable': recoverable,
                **(context or {})
            }
        )
        
        # Trigger error handlers
        self._trigger_error_handlers(error_info)
        
        return error_info
    
    def _generate_error_id(self) -> str:
        """Generate unique error ID"""
        return f"ERR_{int(time.time())}_{threading.get_ident()}"
    
    def _trigger_error_handlers(self, error_info: ErrorInfo):
        """Trigger registered error handlers"""
        handlers = self._error_handlers.get(error_info.category, [])
        handlers.extend(self._error_handlers.get(ErrorCategory.UNKNOWN, []))
        
        for handler in handlers:
            try:
                handler(error_info)
            except Exception as e:
                self.logger.error(f"Error handler failed: {e}")
    
    def register_error_handler(self, category: ErrorCategory, handler: Callable[[ErrorInfo], None]):
        """Register error handler for specific category"""
        if category not in self._error_handlers:
            self._error_handlers[category] = []
        self._error_handlers[category].append(handler)
    
    def register_recovery_strategy(self, category: ErrorCategory, strategy: Callable[[ErrorInfo], bool]):
        """Register recovery strategy for error category"""
        self._recovery_strategies[category] = strategy
    
    def attempt_recovery(self, error_info: ErrorInfo) -> bool:
        """Attempt error recovery using registered strategies"""
        if not error_info.recoverable or error_info.recovery_attempts >= error_info.max_recovery_attempts:
            return False
        
        strategy = self._recovery_strategies.get(error_info.category)
        if not strategy:
            return False
        
        try:
            error_info.recovery_attempts += 1
            success = strategy(error_info)
            
            if success:
                self.error_metrics.record_recovery(error_info.category)
                self.info(f"Successfully recovered from error: {error_info.error_id}")
            else:
                self.warning(f"Recovery attempt failed for error: {error_info.error_id}")
            
            return success
        except Exception as e:
            self.error(f"Recovery strategy failed: {e}")
            return False
    
    def get_error_stats(self) -> Dict[str, Any]:
        """Get error statistics"""
        return self.error_metrics.get_error_stats()
    
    def get_error_history(self, limit: int = 100) -> List[ErrorInfo]:
        """Get error history"""
        return self.error_metrics.get_error_history(limit)


def with_error_handling(severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                       category: ErrorCategory = ErrorCategory.UNKNOWN,
                       recoverable: bool = True,
                       max_retries: int = 0):
    """
    Decorator for automatic error handling
    
    Args:
        severity: Error severity level
        category: Error category
        recoverable: Whether error is recoverable
        max_retries: Maximum retry attempts
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            last_error = None
            
            while retries <= max_retries:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_error = e
                    
                    # Log error
                    logger = get_logger()
                    error_info = logger.log_error(
                        e, 
                        severity=severity,
                        category=category,
                        context={
                            'function': func.__name__,
                            'args_count': len(args),
                            'kwargs_keys': list(kwargs.keys()),
                            'retry_attempt': retries
                        },
                        recoverable=recoverable and retries < max_retries
                    )
                    
                    # Attempt recovery if possible
                    if retries < max_retries and recoverable:
                        if logger.attempt_recovery(error_info):
                            retries += 1
                            continue
                    
                    # No more retries or recovery failed
                    break
                finally:
                    retries += 1
            
            # Re-raise the last error
            raise last_error
        
        return wrapper
    return decorator


# Global logger instance
_global_logger: Optional[EnhancedLogger] = None


def get_logger() -> EnhancedLogger:
    """Get global logger instance"""
    global _global_logger
    if _global_logger is None:
        _global_logger = EnhancedLogger()
    return _global_logger


def init_logging(name: str = "BLNCS", log_dir: str = "logs") -> EnhancedLogger:
    """Initialize global logging system"""
    global _global_logger
    _global_logger = EnhancedLogger(name, log_dir)
    return _global_logger


# Convenience functions
def log_info(message: str, context: Optional[Dict] = None):
    """Log info message using global logger"""
    get_logger().info(message, context)


def log_error(exception: Exception,
              severity: ErrorSeverity = ErrorSeverity.MEDIUM,
              category: ErrorCategory = ErrorCategory.UNKNOWN,
              context: Optional[Dict] = None) -> ErrorInfo:
    """Log error using global logger"""
    return get_logger().log_error(exception, severity, category, context)


def log_warning(message: str, context: Optional[Dict] = None):
    """Log warning message using global logger"""
    get_logger().warning(message, context)


def log_debug(message: str, context: Optional[Dict] = None):
    """Log debug message using global logger"""
    get_logger().debug(message, context)