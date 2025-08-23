"""
Advanced Logging and Audit System
Enterprise-grade logging with complete audit trail
"""

import logging
import json
import time
import sys
import traceback
from datetime import datetime
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import threading
import queue
import hashlib
import socket
import os


class LogLevel(Enum):
    """Log levels"""
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL
    AUDIT = 25  # Between INFO and WARNING


class AuditEventType(Enum):
    """Audit event types"""
    LOGIN = "login"
    LOGOUT = "logout"
    ACCESS = "access"
    MODIFY = "modify"
    DELETE = "delete"
    ADMIN = "admin"
    SECURITY = "security"
    CONFIG = "config"
    ERROR = "error"


@dataclass
class LogContext:
    """Log context information"""
    timestamp: float = field(default_factory=time.time)
    level: LogLevel = LogLevel.INFO
    logger_name: str = ""
    message: str = ""
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    ip_address: Optional[str] = None
    hostname: str = field(default_factory=socket.gethostname)
    process_id: int = field(default_factory=os.getpid)
    thread_id: int = field(default_factory=threading.get_ident)
    extra: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['timestamp_iso'] = datetime.fromtimestamp(self.timestamp).isoformat()
        data['level'] = self.level.name
        return data
    
    def to_json(self) -> str:
        """Convert to JSON"""
        return json.dumps(self.to_dict(), default=str)


@dataclass
class AuditEvent:
    """Audit event"""
    event_id: str
    event_type: AuditEventType
    timestamp: float = field(default_factory=time.time)
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None
    result: str = "success"
    details: Dict[str, Any] = field(default_factory=dict)
    risk_score: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['timestamp_iso'] = datetime.fromtimestamp(self.timestamp).isoformat()
        data['event_type'] = self.event_type.value
        return data
    
    def to_json(self) -> str:
        """Convert to JSON"""
        return json.dumps(self.to_dict(), default=str)
    
    def calculate_hash(self) -> str:
        """Calculate event hash for integrity"""
        event_str = f"{self.event_id}{self.event_type.value}{self.timestamp}{self.user_id}"
        return hashlib.sha256(event_str.encode()).hexdigest()


class LogFormatter:
    """Custom log formatter"""
    
    def __init__(self, format_type: str = "json"):
        self.format_type = format_type
        
    def format(self, log_context: LogContext) -> str:
        """Format log message"""
        if self.format_type == "json":
            return self._format_json(log_context)
        elif self.format_type == "text":
            return self._format_text(log_context)
        elif self.format_type == "syslog":
            return self._format_syslog(log_context)
        else:
            return self._format_json(log_context)
            
    def _format_json(self, log_context: LogContext) -> str:
        """Format as JSON"""
        return log_context.to_json()
        
    def _format_text(self, log_context: LogContext) -> str:
        """Format as text"""
        timestamp = datetime.fromtimestamp(log_context.timestamp).strftime('%Y-%m-%d %H:%M:%S')
        return f"{timestamp} [{log_context.level.name}] {log_context.logger_name}: {log_context.message}"
        
    def _format_syslog(self, log_context: LogContext) -> str:
        """Format for syslog"""
        priority = self._calculate_syslog_priority(log_context.level)
        timestamp = datetime.fromtimestamp(log_context.timestamp).strftime('%b %d %H:%M:%S')
        return f"<{priority}>{timestamp} {log_context.hostname} {log_context.logger_name}[{log_context.process_id}]: {log_context.message}"
        
    def _calculate_syslog_priority(self, level: LogLevel) -> int:
        """Calculate syslog priority"""
        facility = 16  # Local0
        severity_map = {
            LogLevel.DEBUG: 7,
            LogLevel.INFO: 6,
            LogLevel.WARNING: 4,
            LogLevel.ERROR: 3,
            LogLevel.CRITICAL: 2,
            LogLevel.AUDIT: 5
        }
        severity = severity_map.get(level, 6)
        return facility * 8 + severity


class LogHandler:
    """Base log handler"""
    
    def __init__(self, formatter: LogFormatter = None):
        self.formatter = formatter or LogFormatter()
        self.filters = []
        
    def handle(self, log_context: LogContext):
        """Handle log message"""
        if self._should_handle(log_context):
            formatted = self.formatter.format(log_context)
            self._write(formatted)
            
    def _should_handle(self, log_context: LogContext) -> bool:
        """Check if should handle this log"""
        for filter_func in self.filters:
            if not filter_func(log_context):
                return False
        return True
        
    def _write(self, message: str):
        """Write log message - override in subclasses"""
        pass
        
    def add_filter(self, filter_func):
        """Add log filter"""
        self.filters.append(filter_func)


class FileLogHandler(LogHandler):
    """File log handler with rotation"""
    
    def __init__(self, file_path: str, max_size: int = 104857600, 
                 backup_count: int = 10, formatter: LogFormatter = None):
        super().__init__(formatter)
        self.file_path = Path(file_path)
        self.max_size = max_size
        self.backup_count = backup_count
        self.current_size = 0
        self.lock = threading.Lock()
        
        # Create directory if needed
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Get current file size
        if self.file_path.exists():
            self.current_size = self.file_path.stat().st_size
            
    def _write(self, message: str):
        """Write to file with rotation"""
        with self.lock:
            # Check if rotation needed
            if self.current_size >= self.max_size:
                self._rotate()
                
            # Write message
            with open(self.file_path, 'a', encoding='utf-8') as f:
                f.write(message + '\n')
                self.current_size += len(message) + 1
                
    def _rotate(self):
        """Rotate log files"""
        # Move existing backups
        for i in range(self.backup_count - 1, 0, -1):
            old_path = Path(f"{self.file_path}.{i}")
            new_path = Path(f"{self.file_path}.{i + 1}")
            if old_path.exists():
                old_path.rename(new_path)
                
        # Move current file to .1
        if self.file_path.exists():
            self.file_path.rename(Path(f"{self.file_path}.1"))
            
        self.current_size = 0


class ConsoleLogHandler(LogHandler):
    """Console log handler"""
    
    def __init__(self, stream=None, formatter: LogFormatter = None):
        super().__init__(formatter)
        self.stream = stream or sys.stdout
        
    def _write(self, message: str):
        """Write to console"""
        self.stream.write(message + '\n')
        self.stream.flush()


class SyslogHandler(LogHandler):
    """Syslog handler"""
    
    def __init__(self, address: tuple = ('localhost', 514), 
                 formatter: LogFormatter = None):
        super().__init__(formatter or LogFormatter('syslog'))
        self.address = address
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
    def _write(self, message: str):
        """Send to syslog"""
        try:
            self.socket.sendto(message.encode('utf-8'), self.address)
        except Exception:
            pass  # Fail silently


class AsyncLogHandler(LogHandler):
    """Asynchronous log handler"""
    
    def __init__(self, handler: LogHandler, queue_size: int = 10000):
        super().__init__(handler.formatter)
        self.handler = handler
        self.queue = queue.Queue(maxsize=queue_size)
        self.worker_thread = threading.Thread(target=self._worker)
        self.worker_thread.daemon = True
        self.running = True
        self.worker_thread.start()
        
    def _write(self, message: str):
        """Queue message for async writing"""
        try:
            self.queue.put_nowait(message)
        except queue.Full:
            # Drop message if queue is full
            pass
            
    def _worker(self):
        """Worker thread for processing log queue"""
        while self.running:
            try:
                message = self.queue.get(timeout=1)
                self.handler._write(message)
            except queue.Empty:
                continue
                
    def stop(self):
        """Stop async handler"""
        self.running = False
        self.worker_thread.join(timeout=5)


class AuditLogger:
    """Audit logger for compliance"""
    
    def __init__(self, audit_file: str = "/var/log/blrcs/audit.log"):
        self.audit_file = Path(audit_file)
        self.audit_file.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        
    def log_event(self, event: AuditEvent):
        """Log audit event"""
        with self.lock:
            # Add integrity hash
            event_dict = event.to_dict()
            event_dict['integrity_hash'] = event.calculate_hash()
            
            # Write to audit log
            with open(self.audit_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(event_dict, default=str) + '\n')
                
    def create_event(self, event_type: AuditEventType, **kwargs) -> AuditEvent:
        """Create and log audit event"""
        event_id = hashlib.sha256(
            f"{time.time()}{event_type.value}".encode()
        ).hexdigest()[:16]
        
        event = AuditEvent(
            event_id=event_id,
            event_type=event_type,
            **kwargs
        )
        
        self.log_event(event)
        return event
        
    def query_events(self, start_time: float = None, end_time: float = None,
                    event_type: AuditEventType = None, user_id: str = None,
                    limit: int = 100) -> List[AuditEvent]:
        """Query audit events"""
        events = []
        
        if not self.audit_file.exists():
            return events
            
        with open(self.audit_file, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    
                    # Apply filters
                    if start_time and data['timestamp'] < start_time:
                        continue
                    if end_time and data['timestamp'] > end_time:
                        continue
                    if event_type and data['event_type'] != event_type.value:
                        continue
                    if user_id and data.get('user_id') != user_id:
                        continue
                        
                    # Create event object
                    event = AuditEvent(
                        event_id=data['event_id'],
                        event_type=AuditEventType(data['event_type']),
                        timestamp=data['timestamp'],
                        user_id=data.get('user_id'),
                        session_id=data.get('session_id'),
                        ip_address=data.get('ip_address'),
                        resource=data.get('resource'),
                        action=data.get('action'),
                        result=data.get('result', 'success'),
                        details=data.get('details', {}),
                        risk_score=data.get('risk_score', 0)
                    )
                    
                    events.append(event)
                    
                    if len(events) >= limit:
                        break
                        
                except Exception:
                    continue
                    
        return events


class Logger:
    """Main logger class"""
    
    def __init__(self, name: str):
        self.name = name
        self.handlers = []
        self.level = LogLevel.INFO
        self.context = {}
        
    def add_handler(self, handler: LogHandler):
        """Add log handler"""
        self.handlers.append(handler)
        
    def set_level(self, level: LogLevel):
        """Set log level"""
        self.level = level
        
    def set_context(self, **kwargs):
        """Set logging context"""
        self.context.update(kwargs)
        
    def _log(self, level: LogLevel, message: str, **extra):
        """Internal log method"""
        if level.value < self.level.value:
            return
            
        log_context = LogContext(
            level=level,
            logger_name=self.name,
            message=message,
            **self.context,
            extra=extra
        )
        
        for handler in self.handlers:
            try:
                handler.handle(log_context)
            except Exception:
                pass  # Don't fail on logging errors
                
    def debug(self, message: str, **extra):
        """Log debug message"""
        self._log(LogLevel.DEBUG, message, **extra)
        
    def info(self, message: str, **extra):
        """Log info message"""
        self._log(LogLevel.INFO, message, **extra)
        
    def warning(self, message: str, **extra):
        """Log warning message"""
        self._log(LogLevel.WARNING, message, **extra)
        
    def error(self, message: str, exception: Exception = None, **extra):
        """Log error message"""
        if exception:
            extra['exception'] = str(exception)
            extra['traceback'] = traceback.format_exc()
        self._log(LogLevel.ERROR, message, **extra)
        
    def critical(self, message: str, **extra):
        """Log critical message"""
        self._log(LogLevel.CRITICAL, message, **extra)
        
    def audit(self, message: str, **extra):
        """Log audit message"""
        self._log(LogLevel.AUDIT, message, **extra)


class LoggingSystem:
    """Complete logging system"""
    
    def __init__(self):
        self.loggers = {}
        self.audit_logger = AuditLogger()
        self.default_handlers = []
        
        # Setup default handlers
        self._setup_default_handlers()
        
    def _setup_default_handlers(self):
        """Setup default log handlers"""
        # Console handler
        console_handler = ConsoleLogHandler(
            formatter=LogFormatter('text')
        )
        self.default_handlers.append(console_handler)
        
        # File handler
        file_handler = FileLogHandler(
            '/var/log/blrcs/app.log',
            formatter=LogFormatter('json')
        )
        self.default_handlers.append(file_handler)
        
    def get_logger(self, name: str) -> Logger:
        """Get or create logger"""
        if name not in self.loggers:
            logger = Logger(name)
            
            # Add default handlers
            for handler in self.default_handlers:
                logger.add_handler(handler)
                
            self.loggers[name] = logger
            
        return self.loggers[name]
        
    def audit_event(self, event_type: AuditEventType, **kwargs):
        """Log audit event"""
        return self.audit_logger.create_event(event_type, **kwargs)
        
    def get_audit_events(self, **filters) -> List[AuditEvent]:
        """Get audit events"""
        return self.audit_logger.query_events(**filters)


# Global logging system
_logging_system = LoggingSystem()


def get_logger(name: str) -> Logger:
    """Get logger instance"""
    return _logging_system.get_logger(name)


def audit_event(event_type: AuditEventType, **kwargs):
    """Log audit event"""
    return _logging_system.audit_event(event_type, **kwargs)


def setup_logging(log_level: str = "INFO", log_format: str = "json"):
    """Setup logging system"""
    level = LogLevel[log_level.upper()]
    
    # Set level for all loggers
    for logger in _logging_system.loggers.values():
        logger.set_level(level)
        
    # Update formatter
    formatter = LogFormatter(log_format)
    for handler in _logging_system.default_handlers:
        handler.formatter = formatter