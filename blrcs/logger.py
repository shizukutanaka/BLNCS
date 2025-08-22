# BLRCS Logger Module
# Enhanced structured logging with advanced features
import logging
import json
import sys
import re
import threading
import queue
import time
import hashlib
import gzip
import shutil
from pathlib import Path
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Callable, Set
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum

@dataclass
class LogMetrics:
    """Log metrics and analytics"""
    total_logs: int = 0
    error_count: int = 0
    warning_count: int = 0
    critical_count: int = 0
    log_rate: float = 0.0
    error_rate: float = 0.0
    common_errors: Dict[str, int] = field(default_factory=dict)
    peak_times: List[str] = field(default_factory=list)
    last_reset: datetime = field(default_factory=datetime.now)

class LogLevel(Enum):
    """Enhanced log levels"""
    TRACE = 5
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50
    SECURITY = 60
    AUDIT = 70

class LogFilter:
    """Advanced log filtering"""
    
    def __init__(self):
        self.rules: List[Dict[str, Any]] = []
        self.enabled = True
    
    def add_rule(self, level: str = None, logger: str = None, 
                message_pattern: str = None, module: str = None,
                exclude: bool = False):
        """Add filtering rule"""
        rule = {
            'level': level,
            'logger': logger,
            'message_pattern': re.compile(message_pattern) if message_pattern else None,
            'module': module,
            'exclude': exclude
        }
        self.rules.append(rule)
    
    def should_log(self, record: logging.LogRecord) -> bool:
        """Check if record should be logged"""
        if not self.enabled:
            return True
        
        for rule in self.rules:
            matches = True
            
            if rule['level'] and record.levelname != rule['level']:
                matches = False
            
            if rule['logger'] and record.name != rule['logger']:
                matches = False
                
            if rule['module'] and record.module != rule['module']:
                matches = False
                
            if rule['message_pattern'] and not rule['message_pattern'].search(record.getMessage()):
                matches = False
            
            if matches:
                return not rule['exclude']
        
        return True

class LogAggregator:
    """Log aggregation and analysis"""
    
    def __init__(self, window_size: int = 300):
        self.window_size = window_size  # 5 minutes
        self.logs: deque = deque(maxlen=1000)
        self.metrics = LogMetrics()
        self.patterns: Dict[str, int] = defaultdict(int)
        self.lock = threading.Lock()
        
        # Alert thresholds
        self.error_threshold = 10  # errors per minute
        self.warning_threshold = 50  # warnings per minute
        self.alert_callbacks: List[Callable] = []
    
    def add_log(self, record: logging.LogRecord):
        """Add log record for aggregation"""
        with self.lock:
            timestamp = datetime.now()
            log_entry = {
                'timestamp': timestamp,
                'level': record.levelname,
                'logger': record.name,
                'message': record.getMessage(),
                'module': record.module
            }
            
            self.logs.append(log_entry)
            self._update_metrics(log_entry)
            self._check_patterns(log_entry)
            self._check_alerts()
    
    def _update_metrics(self, log_entry: Dict[str, Any]):
        """Update metrics"""
        self.metrics.total_logs += 1
        
        if log_entry['level'] == 'ERROR':
            self.metrics.error_count += 1
        elif log_entry['level'] == 'WARNING':
            self.metrics.warning_count += 1
        elif log_entry['level'] == 'CRITICAL':
            self.metrics.critical_count += 1
    
    def _check_patterns(self, log_entry: Dict[str, Any]):
        """Analyze log patterns"""
        message_hash = hashlib.sha256(log_entry['message'].encode()).hexdigest()[:8]
        self.patterns[message_hash] += 1
        
        # Track common errors
        if log_entry['level'] in ['ERROR', 'CRITICAL']:
            error_key = f"{log_entry['module']}:{message_hash}"
            self.metrics.common_errors[error_key] = self.metrics.common_errors.get(error_key, 0) + 1
    
    def _check_alerts(self):
        """Check for alert conditions"""
        now = datetime.now()
        recent_logs = [log for log in self.logs 
                      if (now - log['timestamp']).total_seconds() < 60]
        
        error_count = sum(1 for log in recent_logs if log['level'] == 'ERROR')
        warning_count = sum(1 for log in recent_logs if log['level'] == 'WARNING')
        
        if error_count >= self.error_threshold:
            self._trigger_alert('HIGH_ERROR_RATE', f'Error rate: {error_count}/min')
        
        if warning_count >= self.warning_threshold:
            self._trigger_alert('HIGH_WARNING_RATE', f'Warning rate: {warning_count}/min')
    
    def _trigger_alert(self, alert_type: str, message: str):
        """Trigger alert callbacks"""
        for callback in self.alert_callbacks:
            try:
                callback(alert_type, message)
            except Exception:
                pass
    
    def add_alert_callback(self, callback: Callable):
        """Add alert callback"""
        self.alert_callbacks.append(callback)
    
    def get_metrics(self) -> LogMetrics:
        """Get current metrics"""
        with self.lock:
            # Calculate rates
            time_diff = (datetime.now() - self.metrics.last_reset).total_seconds()
            if time_diff > 0:
                self.metrics.log_rate = self.metrics.total_logs / (time_diff / 60)
                self.metrics.error_rate = self.metrics.error_count / (time_diff / 60)
            
            return self.metrics
    
    def reset_metrics(self):
        """Reset metrics"""
        with self.lock:
            self.metrics = LogMetrics()

class AsyncLogHandler(logging.Handler):
    """Asynchronous log handler for high-performance logging"""
    
    def __init__(self, target_handler: logging.Handler, queue_size: int = 1000):
        super().__init__()
        self.target_handler = target_handler
        self.log_queue = queue.Queue(maxsize=queue_size)
        self.worker_thread = threading.Thread(target=self._worker, daemon=True)
        self.running = True
        self.worker_thread.start()
    
    def emit(self, record: logging.LogRecord):
        """Emit log record asynchronously"""
        try:
            self.log_queue.put_nowait(record)
        except queue.Full:
            # Drop oldest log if queue is full
            try:
                self.log_queue.get_nowait()
                self.log_queue.put_nowait(record)
            except queue.Empty:
                pass
    
    def _worker(self):
        """Background worker thread"""
        while self.running:
            try:
                record = self.log_queue.get(timeout=1)
                self.target_handler.emit(record)
                self.log_queue.task_done()
            except queue.Empty:
                continue
            except Exception:
                pass
    
    def close(self):
        """Close handler and worker thread"""
        self.running = False
        self.worker_thread.join(timeout=5)
        self.target_handler.close()
        super().close()

class StructuredLogger:
    """Enhanced structured logger with advanced features"""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.filter = LogFilter()
        self.aggregator = LogAggregator()
        self.context: Dict[str, Any] = {}
        self.correlation_id: Optional[str] = None
        
        # Add custom filter
        self.logger.addFilter(self._should_log)
    
    def _should_log(self, record: logging.LogRecord) -> bool:
        """Custom filter function"""
        should_log = self.filter.should_log(record)
        if should_log:
            self.aggregator.add_log(record)
        return should_log
    
    def set_context(self, **kwargs):
        """Set logging context"""
        self.context.update(kwargs)
    
    def clear_context(self):
        """Clear logging context"""
        self.context.clear()
    
    def set_correlation_id(self, correlation_id: str):
        """Set correlation ID for request tracing"""
        self.correlation_id = correlation_id
    
    def _log_with_context(self, level: int, message: str, *args, **kwargs):
        """Log with context and correlation ID"""
        extra = kwargs.get('extra', {})
        extra.update(self.context)
        
        if self.correlation_id:
            extra['correlation_id'] = self.correlation_id
        
        kwargs['extra'] = extra
        self.logger.log(level, message, *args, **kwargs)
    
    def trace(self, message: str, *args, **kwargs):
        """Log trace level"""
        self._log_with_context(LogLevel.TRACE.value, message, *args, **kwargs)
    
    def debug(self, message: str, *args, **kwargs):
        """Log debug level"""
        self._log_with_context(LogLevel.DEBUG.value, message, *args, **kwargs)
    
    def info(self, message: str, *args, **kwargs):
        """Log info level"""
        self._log_with_context(LogLevel.INFO.value, message, *args, **kwargs)
    
    def warning(self, message: str, *args, **kwargs):
        """Log warning level"""
        self._log_with_context(LogLevel.WARNING.value, message, *args, **kwargs)
    
    def error(self, message: str, *args, **kwargs):
        """Log error level"""
        self._log_with_context(LogLevel.ERROR.value, message, *args, **kwargs)
    
    def critical(self, message: str, *args, **kwargs):
        """Log critical level"""
        self._log_with_context(LogLevel.CRITICAL.value, message, *args, **kwargs)
    
    def security(self, message: str, *args, **kwargs):
        """Log security events"""
        extra = kwargs.get('extra', {})
        extra['security_event'] = True
        kwargs['extra'] = extra
        self._log_with_context(LogLevel.SECURITY.value, message, *args, **kwargs)
    
    def audit(self, message: str, *args, **kwargs):
        """Log audit events"""
        extra = kwargs.get('extra', {})
        extra['audit_event'] = True
        kwargs['extra'] = extra
        self._log_with_context(LogLevel.AUDIT.value, message, *args, **kwargs)

def setup_logging(level: str = "INFO", log_file: Optional[Path] = None, 
                 enable_async: bool = True, enable_aggregation: bool = True):
    """Setup enhanced application logging"""
    # Add custom log levels
    logging.addLevelName(LogLevel.TRACE.value, 'TRACE')
    logging.addLevelName(LogLevel.SECURITY.value, 'SECURITY')
    logging.addLevelName(LogLevel.AUDIT.value, 'AUDIT')
    
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # Create enhanced formatter
    formatter = EnhancedJsonFormatter()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)
    
    # Wrap with async handler if enabled
    if enable_async:
        console_handler = AsyncLogHandler(console_handler)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers.clear()
    root_logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = EnhancedRotatingFileHandler(
            str(log_file),
            maxBytes=10_000_000,  # 10MB
            backupCount=10,
            encoding='utf-8'
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(log_level)
        
        # Wrap with async handler if enabled
        if enable_async:
            file_handler = AsyncLogHandler(file_handler)
        
        root_logger.addHandler(file_handler)
    
    # Start log rotation
    if log_file:
        rotator = get_log_rotator()
        rotator.start_auto_rotation()
    
    # Global aggregator setup
    if enable_aggregation:
        global _global_aggregator
        _global_aggregator = LogAggregator()
        
        # Add aggregation to root logger
        class AggregationHandler(logging.Handler):
            def emit(self, record):
                _global_aggregator.add_log(record)
        
        root_logger.addHandler(AggregationHandler())

class EnhancedJsonFormatter(logging.Formatter):
    """JSON log formatter for structured logging"""
    
    # Keys whose values should be redacted in logs
    _SENSITIVE_KEYS = {
        "password", "pass", "secret", "token", "api_key", "apikey", "macaroon",
        "certificate", "cert", "private_key", "seed", "mnemonic", "key",
    }
    # Simple patterns like key=value or "key":"value" to redact in message strings
    _MSG_RE_PATTERNS = [
        re.compile(r"(?i)(password|pass|secret|token|api[_-]?key|macaroon|private[_-]?key|seed|mnemonic)\s*[:=]\s*([^\s,;\"]+)")
    ]

    @classmethod
    def _redact_obj(cls, obj: Any) -> Any:
        # Redact strings heuristically
        if isinstance(obj, str):
            s = obj
            for pat in cls._MSG_RE_PATTERNS:
                s = pat.sub(lambda m: f"{m.group(1)}=<redacted>", s)
            return s
        # Redact dict values by sensitive key names
        if isinstance(obj, dict):
            redacted: Dict[str, Any] = {}
            for k, v in obj.items():
                if isinstance(k, str) and k.lower() in cls._SENSITIVE_KEYS:
                    redacted[k] = "<redacted>"
                else:
                    redacted[k] = cls._redact_obj(v)
            return redacted
        # Redact list/tuple recursively
        if isinstance(obj, (list, tuple)):
            return [cls._redact_obj(v) for v in obj]
        return obj

    def format(self, record: logging.LogRecord) -> str:
        log_obj: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": self._redact_obj(record.getMessage()),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "thread": record.thread,
            "thread_name": record.threadName,
            "process": record.process
        }
        
        # Add severity score
        severity_map = {
            'TRACE': 1, 'DEBUG': 2, 'INFO': 3, 'WARNING': 4,
            'ERROR': 5, 'CRITICAL': 6, 'SECURITY': 7, 'AUDIT': 8
        }
        log_obj["severity"] = severity_map.get(record.levelname, 3)
        
        # Add extra fields
        if hasattr(record, 'extra'):
            try:
                extra_data = self._redact_obj(record.extra)
                log_obj.update(extra_data)
            except Exception:
                log_obj.update(record.extra)
        
        # Add exception info if present
        if record.exc_info:
            try:
                log_obj["exception"] = {
                    "type": record.exc_info[0].__name__,
                    "message": str(record.exc_info[1]),
                    "traceback": self._redact_obj(self.formatException(record.exc_info))
                }
            except Exception:
                log_obj["exception"] = self.formatException(record.exc_info)
        
        # Add performance timing if available
        if hasattr(record, 'duration'):
            log_obj["duration_ms"] = record.duration
        
        # Add stack info for debug
        if record.levelno <= logging.DEBUG and record.stack_info:
            log_obj["stack_info"] = self._redact_obj(record.stack_info)
        
        return json.dumps(log_obj, ensure_ascii=False, separators=(',', ':'))

class EnhancedRotatingFileHandler(RotatingFileHandler):
    """Enhanced rotating file handler with compression"""
    
    def __init__(self, filename, mode='a', maxBytes=0, backupCount=0, 
                 encoding=None, delay=False, compress=True):
        super().__init__(filename, mode, maxBytes, backupCount, encoding, delay)
        self.compress = compress
    
    def doRollover(self):
        """Enhanced rollover with compression"""
        if self.stream:
            self.stream.close()
            self.stream = None
        
        if self.backupCount > 0:
            for i in range(self.backupCount - 1, 0, -1):
                sfn = self.rotation_filename("%s.%d" % (self.baseFilename, i))
                dfn = self.rotation_filename("%s.%d" % (self.baseFilename, i + 1))
                
                if self.compress:
                    sfn += '.gz'
                    dfn += '.gz'
                
                if Path(sfn).exists():
                    if Path(dfn).exists():
                        Path(dfn).unlink()
                    Path(sfn).rename(dfn)
            
            dfn = self.rotation_filename(self.baseFilename + ".1")
            
            if self.compress:
                # Compress the file
                # パス正規化でパストラバーサル防止
                safe_base = Path(self.baseFilename).resolve()
                safe_dest = Path(dfn + '.gz').resolve()
                with open(safe_base, 'rb') as f_in:
                    with gzip.open(safe_dest, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                Path(self.baseFilename).unlink()
            else:
                if Path(dfn).exists():
                    Path(dfn).unlink()
                Path(self.baseFilename).rename(dfn)
        
        if not self.delay:
            self.stream = self._open()

def get_logger(name: str) -> StructuredLogger:
    """Get enhanced logger instance"""
    return StructuredLogger(name)

def get_standard_logger(name: str) -> logging.Logger:
    """Get standard logger instance"""
    return logging.getLogger(name)

# Performance logging utilities
class PerformanceLogger:
    """Performance logging for method timing"""
    
    def __init__(self, logger: StructuredLogger):
        self.logger = logger
    
    def time_method(self, method_name: str):
        """Decorator for method timing"""
        def decorator(func):
            def wrapper(*args, **kwargs):
                start_time = time.time()
                try:
                    result = func(*args, **kwargs)
                    duration = (time.time() - start_time) * 1000
                    self.logger.debug(f"{method_name} completed", 
                                    extra={'duration_ms': duration, 'method': method_name})
                    return result
                except Exception as e:
                    duration = (time.time() - start_time) * 1000
                    self.logger.error(f"{method_name} failed: {str(e)}", 
                                    extra={'duration_ms': duration, 'method': method_name})
                    raise
            return wrapper
        return decorator

# Global instances
_global_aggregator: Optional[LogAggregator] = None

def get_log_aggregator() -> Optional[LogAggregator]:
    """Get global log aggregator"""
    return _global_aggregator

def get_log_metrics() -> Optional[LogMetrics]:
    """Get current log metrics"""
    if _global_aggregator:
        return _global_aggregator.get_metrics()
    return None

class LogRotator:
    """
    Simple and efficient log rotation.
    No external dependencies.
    """
    
    def __init__(self, log_dir: Path = Path("logs")):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        self.config = {
            'max_size': 10 * 1024 * 1024,  # 10MB
            'max_files': 7,  # Keep 7 old logs
            'max_age_days': 30,
            'compress': True,
            'date_format': '%Y%m%d',
            'check_interval': 3600  # Check every hour
        }
        
        self.running = False
        self.thread: Optional[threading.Thread] = None
    
    def should_rotate(self, log_file: Path) -> bool:
        """Check if log file should be rotated"""
        if not log_file.exists():
            return False
        
        # Check size
        if log_file.stat().st_size >= self.config['max_size']:
            return True
        
        # Check age (daily rotation)
        file_date = datetime.fromtimestamp(log_file.stat().st_mtime).date()
        if file_date < datetime.now().date():
            return True
        
        return False
    
    def rotate_file(self, log_file: Path):
        """Rotate a log file"""
        if not log_file.exists():
            return
        
        # Generate rotation name
        timestamp = datetime.now().strftime(self.config['date_format'])
        base_name = log_file.stem
        
        # Find available rotation number
        n = 1
        while True:
            rotate_name = f"{base_name}.{timestamp}.{n}"
            if self.config['compress']:
                rotate_name += ".gz"
            
            rotate_path = log_file.parent / rotate_name
            if not rotate_path.exists():
                break
            n += 1
        
        # Rotate the file
        if self.config['compress']:
            # Compress and rotate
            with open(log_file, 'rb') as f_in:
                with gzip.open(rotate_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # Clear original file
            open(log_file, 'w').close()
        else:
            # Simple rename
            shutil.move(str(log_file), str(rotate_path))
            
    def cleanup_old_logs(self):
        """Remove old log files"""
        cutoff_time = time.time() - (self.config['max_age_days'] * 86400)
        
        for log_file in self.log_dir.glob("*.log*"):
            if log_file.stat().st_mtime < cutoff_time:
                try:
                    log_file.unlink()
                except:
                    pass
    
    def start_auto_rotation(self):
        """Start automatic rotation thread"""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._rotation_loop, daemon=True)
        self.thread.start()
    
    def stop_auto_rotation(self):
        """Stop automatic rotation"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)
    
    def _rotation_loop(self):
        """Background rotation loop"""
        while self.running:
            try:
                # Check all log files
                for log_file in self.log_dir.glob("*.log"):
                    if self.should_rotate(log_file):
                        self.rotate_file(log_file)
                
                # Cleanup old files
                self.cleanup_old_logs()
                
            except Exception:
                pass
            
            # Wait for next check
            time.sleep(self.config['check_interval'])

# Global log rotator instance
_log_rotator: Optional[LogRotator] = None

def get_log_rotator(log_dir: Optional[Path] = None) -> LogRotator:
    """Get global log rotator instance"""
    global _log_rotator
    if _log_rotator is None:
        _log_rotator = LogRotator(log_dir or Path("logs"))
    return _log_rotator

def create_correlation_id() -> str:
    """Create unique correlation ID for request tracing"""
    return hashlib.sha256(f"{time.time()}_{threading.current_thread().ident}".encode()).hexdigest()[:12]

def log_request(logger: StructuredLogger, method: str, url: str, duration: float = None):
    """Log HTTP request"""
    extra = {'request_method': method, 'request_url': url}
    if duration is not None:
        extra['duration_ms'] = duration * 1000
    logger.info(f"{method} {url}", extra=extra)

def log_database_query(logger: StructuredLogger, query: str, duration: float = None, rows: int = None):
    """Log database query"""
    extra = {'query_type': query.split()[0].upper() if query else 'UNKNOWN'}
    if duration is not None:
        extra['duration_ms'] = duration * 1000
    if rows is not None:
        extra['rows_affected'] = rows
    logger.debug(f"Database query: {query[:100]}...", extra=extra)

def shutdown_logging():
    """Shutdown logging system gracefully"""
    global _log_rotator, _global_aggregator
    
    if _log_rotator:
        _log_rotator.stop_auto_rotation()
    
    # Close all handlers
    for handler in logging.getLogger().handlers[:]:
        if isinstance(handler, AsyncLogHandler):
            handler.close()
        logging.getLogger().removeHandler(handler)
    
    logging.shutdown()
