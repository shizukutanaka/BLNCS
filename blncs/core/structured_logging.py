"""
Structured Logging System for BLNCS
Enterprise-grade logging with correlation IDs, structured data, and observability integration.
"""

import json
import time
import uuid
import threading
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional, Union, List, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from contextlib import contextmanager, asynccontextmanager
import logging
import logging.handlers
from pathlib import Path

from .error_handler import get_error_handler
from .async_metrics import get_metrics_collector


class LogLevel(Enum):
    """Enhanced log levels with numeric values"""
    TRACE = 5
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50
    AUDIT = 60  # Special level for audit events


class LogCategory(Enum):
    """Log categories for better organization"""
    SYSTEM = "system"
    SECURITY = "security"
    LIGHTNING = "lightning"
    DATABASE = "database"
    API = "api"
    PERFORMANCE = "performance"
    AUDIT = "audit"
    USER = "user"
    NETWORK = "network"
    BUSINESS = "business"


@dataclass
class LogContext:
    """Structured log context with correlation tracking"""
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    request_id: Optional[str] = None
    operation: Optional[str] = None
    component: Optional[str] = None
    version: str = "2.0.0"
    environment: str = "production"
    node_id: Optional[str] = None
    channel_id: Optional[str] = None
    transaction_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary for logging"""
        return {k: v for k, v in asdict(self).items() if v is not None}
    
    def update(self, **kwargs) -> 'LogContext':
        """Create new context with updated fields"""
        data = asdict(self)
        data.update(kwargs)
        return LogContext(**data)


@dataclass
class StructuredLogEntry:
    """Structured log entry with all metadata"""
    timestamp: datetime = field(default_factory=datetime.now)
    level: LogLevel = LogLevel.INFO
    category: LogCategory = LogCategory.SYSTEM
    message: str = ""
    context: LogContext = field(default_factory=LogContext)
    data: Dict[str, Any] = field(default_factory=dict)
    exception: Optional[Dict[str, Any]] = None
    duration_ms: Optional[float] = None
    tags: List[str] = field(default_factory=list)
    metrics: Dict[str, float] = field(default_factory=dict)
    
    def to_json(self) -> str:
        """Convert to JSON string for structured logging"""
        entry = {
            'timestamp': self.timestamp.isoformat(),
            'level': self.level.name,
            'category': self.category.value,
            'message': self.message,
            'context': self.context.to_dict(),
            'data': self.data,
            'tags': self.tags
        }
        
        if self.exception:
            entry['exception'] = self.exception
        
        if self.duration_ms is not None:
            entry['duration_ms'] = self.duration_ms
        
        if self.metrics:
            entry['metrics'] = self.metrics
        
        return json.dumps(entry, default=str, ensure_ascii=False)


class StructuredLogger:
    """High-performance structured logger with correlation tracking"""
    
    def __init__(
        self,
        name: str,
        level: LogLevel = LogLevel.INFO,
        output_file: Optional[str] = None,
        max_file_size: int = 100 * 1024 * 1024,  # 100MB
        backup_count: int = 5,
        enable_console: bool = True,
        enable_metrics: bool = True
    ):
        self.name = name
        self.level = level
        self.enable_metrics = enable_metrics
        
        # Thread-safe context storage
        self._local = threading.local()
        self._async_context: Dict[asyncio.Task, LogContext] = {}
        self._context_lock = threading.RLock()
        
        # Setup Python logger
        self.python_logger = logging.getLogger(name)
        self.python_logger.setLevel(level.value)
        self.python_logger.handlers.clear()  # Remove existing handlers
        
        # JSON formatter for structured output
        formatter = logging.Formatter('%(message)s')
        
        # Console handler
        if enable_console:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.python_logger.addHandler(console_handler)
        
        # File handler with rotation
        if output_file:
            file_path = Path(output_file)
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.handlers.RotatingFileHandler(
                output_file,
                maxBytes=max_file_size,
                backupCount=backup_count,
                encoding='utf-8'
            )
            file_handler.setFormatter(formatter)
            self.python_logger.addHandler(file_handler)
        
        # Performance tracking
        self.log_count = 0
        self.error_count = 0
        self.last_flush_time = time.time()
        
        # Async components
        self.metrics_collector = None
        
        # Log processors
        self.processors: List[Callable[[StructuredLogEntry], None]] = []
    
    async def initialize_async(self):
        """Initialize async components"""
        try:
            if self.enable_metrics:
                self.metrics_collector = await get_metrics_collector()
        except Exception:
            pass  # Metrics are optional
    
    def add_processor(self, processor: Callable[[StructuredLogEntry], None]):
        """Add log entry processor"""
        self.processors.append(processor)
    
    def get_context(self) -> LogContext:
        """Get current log context"""
        # Try async context first
        try:
            task = asyncio.current_task()
            if task and task in self._async_context:
                return self._async_context[task]
        except RuntimeError:
            pass  # Not in async context
        
        # Fall back to thread-local context
        if not hasattr(self._local, 'context'):
            self._local.context = LogContext()
        return self._local.context
    
    def set_context(self, context: LogContext):
        """Set current log context"""
        try:
            task = asyncio.current_task()
            if task:
                with self._context_lock:
                    self._async_context[task] = context
                return
        except RuntimeError:
            pass
        
        # Thread-local storage
        self._local.context = context
    
    @contextmanager
    def context(self, **kwargs):
        """Context manager for temporary context updates"""
        old_context = self.get_context()
        new_context = old_context.update(**kwargs)
        
        try:
            self.set_context(new_context)
            yield new_context
        finally:
            self.set_context(old_context)
    
    @asynccontextmanager
    async def async_context(self, **kwargs):
        """Async context manager for temporary context updates"""
        old_context = self.get_context()
        new_context = old_context.update(**kwargs)
        
        try:
            self.set_context(new_context)
            yield new_context
        finally:
            self.set_context(old_context)
    
    def _create_entry(
        self,
        level: LogLevel,
        message: str,
        category: LogCategory = LogCategory.SYSTEM,
        data: Optional[Dict[str, Any]] = None,
        exception: Optional[Exception] = None,
        duration_ms: Optional[float] = None,
        tags: Optional[List[str]] = None,
        metrics: Optional[Dict[str, float]] = None
    ) -> StructuredLogEntry:
        """Create structured log entry"""
        
        # Format exception data
        exception_data = None
        if exception:
            exception_data = {
                'type': type(exception).__name__,
                'message': str(exception),
                'module': getattr(exception, '__module__', 'unknown')
            }
        
        return StructuredLogEntry(
            level=level,
            category=category,
            message=message,
            context=self.get_context(),
            data=data or {},
            exception=exception_data,
            duration_ms=duration_ms,
            tags=tags or [],
            metrics=metrics or {}
        )
    
    def _log_entry(self, entry: StructuredLogEntry):
        """Log structured entry"""
        if entry.level.value < self.level.value:
            return
        
        # Process entry through processors
        for processor in self.processors:
            try:
                processor(entry)
            except Exception:
                pass  # Don't let processor errors break logging
        
        # Log to Python logger
        json_message = entry.to_json()
        self.python_logger.log(entry.level.value, json_message)
        
        # Update statistics
        self.log_count += 1
        if entry.level.value >= LogLevel.ERROR.value:
            self.error_count += 1
        
        # Record metrics
        if self.metrics_collector:
            try:
                asyncio.create_task(self._record_log_metrics(entry))
            except RuntimeError:
                pass  # Not in event loop
    
    async def _record_log_metrics(self, entry: StructuredLogEntry):
        """Record logging metrics"""
        try:
            await self.metrics_collector.record_counter(
                "log_entries_total",
                1.0,
                labels={
                    "level": entry.level.name.lower(),
                    "category": entry.category.value,
                    "logger": self.name
                }
            )
            
            if entry.duration_ms is not None:
                await self.metrics_collector.record_histogram(
                    "operation_duration_ms",
                    entry.duration_ms,
                    labels={
                        "operation": entry.context.operation or "unknown",
                        "component": entry.context.component or "unknown"
                    }
                )
        
        except Exception:
            pass  # Metrics are best-effort
    
    # Logging methods
    
    def trace(
        self,
        message: str,
        category: LogCategory = LogCategory.SYSTEM,
        data: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        """Log trace message"""
        entry = self._create_entry(LogLevel.TRACE, message, category, data, **kwargs)
        self._log_entry(entry)
    
    def debug(
        self,
        message: str,
        category: LogCategory = LogCategory.SYSTEM,
        data: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        """Log debug message"""
        entry = self._create_entry(LogLevel.DEBUG, message, category, data, **kwargs)
        self._log_entry(entry)
    
    def info(
        self,
        message: str,
        category: LogCategory = LogCategory.SYSTEM,
        data: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        """Log info message"""
        entry = self._create_entry(LogLevel.INFO, message, category, data, **kwargs)
        self._log_entry(entry)
    
    def warning(
        self,
        message: str,
        category: LogCategory = LogCategory.SYSTEM,
        data: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        """Log warning message"""
        entry = self._create_entry(LogLevel.WARNING, message, category, data, **kwargs)
        self._log_entry(entry)
    
    def error(
        self,
        message: str,
        category: LogCategory = LogCategory.SYSTEM,
        data: Optional[Dict[str, Any]] = None,
        exception: Optional[Exception] = None,
        **kwargs
    ):
        """Log error message"""
        entry = self._create_entry(LogLevel.ERROR, message, category, data, exception, **kwargs)
        self._log_entry(entry)
    
    def critical(
        self,
        message: str,
        category: LogCategory = LogCategory.SYSTEM,
        data: Optional[Dict[str, Any]] = None,
        exception: Optional[Exception] = None,
        **kwargs
    ):
        """Log critical message"""
        entry = self._create_entry(LogLevel.CRITICAL, message, category, data, exception, **kwargs)
        self._log_entry(entry)
    
    def audit(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        """Log audit event"""
        entry = self._create_entry(LogLevel.AUDIT, message, LogCategory.AUDIT, data, **kwargs)
        self._log_entry(entry)
    
    # Timing context managers
    
    @contextmanager
    def timer(
        self,
        operation: str,
        category: LogCategory = LogCategory.PERFORMANCE,
        level: LogLevel = LogLevel.INFO
    ):
        """Context manager for timing operations"""
        start_time = time.time()
        
        with self.context(operation=operation):
            try:
                yield
                duration_ms = (time.time() - start_time) * 1000
                
                entry = self._create_entry(
                    level,
                    f"Operation completed: {operation}",
                    category,
                    duration_ms=duration_ms,
                    metrics={"duration_ms": duration_ms}
                )
                self._log_entry(entry)
                
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                
                entry = self._create_entry(
                    LogLevel.ERROR,
                    f"Operation failed: {operation}",
                    category,
                    exception=e,
                    duration_ms=duration_ms
                )
                self._log_entry(entry)
                raise
    
    @asynccontextmanager
    async def async_timer(
        self,
        operation: str,
        category: LogCategory = LogCategory.PERFORMANCE,
        level: LogLevel = LogLevel.INFO
    ):
        """Async context manager for timing operations"""
        start_time = time.time()
        
        async with self.async_context(operation=operation):
            try:
                yield
                duration_ms = (time.time() - start_time) * 1000
                
                entry = self._create_entry(
                    level,
                    f"Operation completed: {operation}",
                    category,
                    duration_ms=duration_ms,
                    metrics={"duration_ms": duration_ms}
                )
                self._log_entry(entry)
                
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                
                entry = self._create_entry(
                    LogLevel.ERROR,
                    f"Operation failed: {operation}",
                    category,
                    exception=e,
                    duration_ms=duration_ms
                )
                self._log_entry(entry)
                raise
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get logger statistics"""
        return {
            'name': self.name,
            'level': self.level.name,
            'log_count': self.log_count,
            'error_count': self.error_count,
            'error_rate': self.error_count / max(self.log_count, 1),
            'processors_count': len(self.processors),
            'last_flush_time': self.last_flush_time
        }
    
    def cleanup_async_contexts(self):
        """Clean up completed async contexts"""
        with self._context_lock:
            completed_tasks = [
                task for task in self._async_context.keys()
                if task.done()
            ]
            
            for task in completed_tasks:
                del self._async_context[task]


class LoggerManager:
    """Manager for structured loggers"""
    
    def __init__(self):
        self.loggers: Dict[str, StructuredLogger] = {}
        self.default_level = LogLevel.INFO
        self.default_output_dir = Path("logs")
        self.global_processors: List[Callable] = []
    
    def get_logger(
        self,
        name: str,
        level: Optional[LogLevel] = None,
        category: Optional[LogCategory] = None,
        **kwargs
    ) -> StructuredLogger:
        """Get or create structured logger"""
        
        if name in self.loggers:
            return self.loggers[name]
        
        # Create output file path
        output_file = None
        if 'output_file' not in kwargs:
            output_file = str(self.default_output_dir / f"{name.replace('.', '_')}.log")
        
        logger = StructuredLogger(
            name=name,
            level=level or self.default_level,
            output_file=output_file,
            **kwargs
        )
        
        # Add global processors
        for processor in self.global_processors:
            logger.add_processor(processor)
        
        self.loggers[name] = logger
        return logger
    
    def add_global_processor(self, processor: Callable[[StructuredLogEntry], None]):
        """Add processor to all loggers"""
        self.global_processors.append(processor)
        
        for logger in self.loggers.values():
            logger.add_processor(processor)
    
    def set_global_level(self, level: LogLevel):
        """Set level for all loggers"""
        self.default_level = level
        
        for logger in self.loggers.values():
            logger.level = level
            logger.python_logger.setLevel(level.value)
    
    async def initialize_all_async(self):
        """Initialize async components for all loggers"""
        for logger in self.loggers.values():
            await logger.initialize_async()
    
    def cleanup_all_async_contexts(self):
        """Cleanup async contexts for all loggers"""
        for logger in self.loggers.values():
            logger.cleanup_async_contexts()


# Global logger manager
_global_logger_manager: Optional[LoggerManager] = None


def get_logger_manager() -> LoggerManager:
    """Get global logger manager"""
    global _global_logger_manager
    if _global_logger_manager is None:
        _global_logger_manager = LoggerManager()
    return _global_logger_manager


def get_structured_logger(name: str, **kwargs) -> StructuredLogger:
    """Get structured logger instance"""
    manager = get_logger_manager()
    return manager.get_logger(name, **kwargs)


# Convenience functions and decorators

def log_function_call(
    logger: Optional[StructuredLogger] = None,
    level: LogLevel = LogLevel.DEBUG,
    category: LogCategory = LogCategory.SYSTEM,
    include_args: bool = False,
    include_result: bool = False
):
    """Decorator to log function calls"""
    def decorator(func):
        nonlocal logger
        if logger is None:
            logger = get_structured_logger(func.__module__)
        
        def sync_wrapper(*args, **kwargs):
            function_name = f"{func.__module__}.{func.__name__}"
            
            log_data = {}
            if include_args:
                log_data['args'] = args
                log_data['kwargs'] = kwargs
            
            with logger.timer(function_name, category, level):
                result = func(*args, **kwargs)
                
                if include_result:
                    log_data['result'] = result
                
                if log_data:
                    logger._create_entry(
                        level,
                        f"Function call: {function_name}",
                        category,
                        data=log_data
                    )
                
                return result
        
        async def async_wrapper(*args, **kwargs):
            function_name = f"{func.__module__}.{func.__name__}"
            
            log_data = {}
            if include_args:
                log_data['args'] = args
                log_data['kwargs'] = kwargs
            
            async with logger.async_timer(function_name, category, level):
                result = await func(*args, **kwargs)
                
                if include_result:
                    log_data['result'] = result
                
                if log_data:
                    logger._create_entry(
                        level,
                        f"Function call: {function_name}",
                        category,
                        data=log_data
                    )
                
                return result
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


__all__ = [
    'LogLevel',
    'LogCategory',
    'LogContext',
    'StructuredLogEntry',
    'StructuredLogger',
    'LoggerManager',
    'get_logger_manager',
    'get_structured_logger',
    'log_function_call'
]