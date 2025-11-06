#!/usr/bin/env python3
"""
Unified Logging System for BLNCS
統一されたログシステム - 包括的なログ管理機能付き
"""

import os
import sys
import logging
import json
import asyncio
import gzip
import shutil
import re
import time
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Union, Callable
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
import traceback
from collections import defaultdict, deque

# Try to import structlog for structured logging
try:
    import structlog
    HAS_STRUCTLOG = True
except ImportError:
    HAS_STRUCTLOG = False

from dataclasses import dataclass, field


@dataclass
class LogConfig:
    """Log configuration"""
    file_path: str
    max_size_mb: int = 100
    backup_count: int = 10
    rotation_interval: str = "daily"  # daily, weekly, monthly
    compression: bool = True
    level: str = "INFO"
    format_string: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


@dataclass
class LogRotationResult:
    """Log rotation operation result"""
    success: bool
    rotated_files: List[str] = field(default_factory=list)
    total_size_before: int = 0
    total_size_after: int = 0
    error_message: Optional[str] = None


class ColoredFormatter(logging.Formatter):
    """Colored formatter for console output"""

    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
        'RESET': '\033[0m'       # Reset
    }

    def __init__(self, fmt: Optional[str] = None, use_colors: bool = True):
        super().__init__(fmt)
        self.use_colors = use_colors and sys.stdout.isatty()

    def format(self, record: logging.LogRecord) -> str:
        if self.use_colors:
            levelname = record.levelname
            if levelname in self.COLORS:
                record.levelname = f"{self.COLORS[levelname]}{levelname}{self.COLORS['RESET']}"
                record.msg = f"{self.COLORS[levelname]}{record.msg}{self.COLORS['RESET']}"
        return super().format(record)


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging"""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }

        # Add extra fields
        if hasattr(record, 'extra_fields'):
            log_data.update(record.extra_fields)

        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)

        return json.dumps(log_data)


class UnifiedLogger:
    """
    Unified logging system with support for multiple outputs and formats
    """

    def __init__(
        self,
        name: str,
        level: Union[str, int] = "INFO",
        log_dir: Optional[str] = None,
        console: bool = True,
        file: bool = True,
        json_format: bool = False,
        max_bytes: int = 10 * 1024 * 1024,  # 10MB
        backup_count: int = 5,
        use_structlog: bool = False
    ):
        self.name = name
        self.level = self._parse_level(level)
        self.log_dir = Path(log_dir) if log_dir else Path.cwd() / "logs"
        self.console = console
        self.file = file
        self.json_format = json_format
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.use_structlog = use_structlog and HAS_STRUCTLOG

        # Create log directory if needed
        if self.file:
            self.log_dir.mkdir(parents=True, exist_ok=True)

        # Setup the logger
        self.logger = self._setup_logger()

    def _parse_level(self, level: Union[str, int]) -> int:
        """Parse log level from string or int"""
        if isinstance(level, str):
            return getattr(logging, level.upper(), logging.INFO)
        return level

    def _setup_logger(self) -> Union[logging.Logger, Any]:
        """Setup the logger with handlers and formatters"""
        if self.use_structlog:
            return self._setup_structlog()
        else:
            return self._setup_standard_logger()

    def _setup_standard_logger(self) -> logging.Logger:
        """Setup standard Python logger"""
        logger = logging.getLogger(self.name)
        logger.setLevel(self.level)
        logger.handlers.clear()

        # Console handler
        if self.console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(self.level)

            if self.json_format:
                console_formatter = JSONFormatter()
            else:
                console_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                console_formatter = ColoredFormatter(console_format)

            console_handler.setFormatter(console_formatter)
            logger.addHandler(console_handler)

        # File handler
        if self.file:
            log_file = self.log_dir / f"{self.name.replace('.', '_')}.log"
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=self.max_bytes,
                backupCount=self.backup_count
            )
            file_handler.setLevel(self.level)

            if self.json_format:
                file_formatter = JSONFormatter()
            else:
                file_format = "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s"
                file_formatter = logging.Formatter(file_format)

            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)

        return logger

    def _setup_structlog(self):
        """Setup structlog for structured logging"""
        processors = [
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
        ]

        if self.json_format:
            processors.append(structlog.processors.JSONRenderer())
        else:
            processors.append(structlog.dev.ConsoleRenderer())

        structlog.configure(
            processors=processors,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )

        return structlog.get_logger(self.name)

    def debug(self, message: str, **kwargs):
        """Log debug message"""
        if self.use_structlog:
            self.logger.debug(message, **kwargs)
        else:
            self.logger.debug(message, extra={'extra_fields': kwargs})

    def info(self, message: str, **kwargs):
        """Log info message"""
        if self.use_structlog:
            self.logger.info(message, **kwargs)
        else:
            self.logger.info(message, extra={'extra_fields': kwargs})

    def warning(self, message: str, **kwargs):
        """Log warning message"""
        if self.use_structlog:
            self.logger.warning(message, **kwargs)
        else:
            self.logger.warning(message, extra={'extra_fields': kwargs})

    def error(self, message: str, exc_info: bool = False, **kwargs):
        """Log error message"""
        if self.use_structlog:
            self.logger.error(message, exc_info=exc_info, **kwargs)
        else:
            self.logger.error(message, exc_info=exc_info, extra={'extra_fields': kwargs})

    def critical(self, message: str, exc_info: bool = False, **kwargs):
        """Log critical message"""
        if self.use_structlog:
            self.logger.critical(message, exc_info=exc_info, **kwargs)
        else:
            self.logger.critical(message, exc_info=exc_info, extra={'extra_fields': kwargs})

    def exception(self, message: str, **kwargs):
        """Log exception with traceback"""
        if self.use_structlog:
            self.logger.exception(message, **kwargs)
        else:
            self.logger.exception(message, extra={'extra_fields': kwargs})

    def log_performance(self, operation: str, duration: float, **kwargs):
        """Log performance metrics"""
        self.info(
            f"Performance: {operation}",
            operation=operation,
            duration_ms=duration * 1000,
            **kwargs
        )

    def log_transaction(self, tx_type: str, amount: int, **kwargs):
        """Log Lightning transaction"""
        self.info(
            f"Transaction: {tx_type}",
            transaction_type=tx_type,
            amount_sats=amount,
            **kwargs
        )

    def log_channel_event(self, event: str, channel_id: str, **kwargs):
        """Log channel event"""
        self.info(
            f"Channel Event: {event}",
            event=event,
            channel_id=channel_id,
            **kwargs
        )

    def log_api_request(self, method: str, path: str, status: int, duration: float, **kwargs):
        """Log API request"""
        self.info(
            f"API Request: {method} {path}",
            method=method,
            path=path,
            status_code=status,
            duration_ms=duration * 1000,
            **kwargs
        )

    def set_level(self, level: Union[str, int]):
        """Change log level dynamically"""
        self.level = self._parse_level(level)
        if not self.use_structlog:
            self.logger.setLevel(self.level)
            for handler in self.logger.handlers:
                handler.setLevel(self.level)


# Logger cache
_loggers: Dict[str, UnifiedLogger] = {}

def get_logger(
    name: Optional[str] = None,
    level: Union[str, int] = "INFO",
    **kwargs
) -> UnifiedLogger:
    """
    Get or create a logger instance

    Args:
        name: Logger name (defaults to module name)
        level: Log level
        **kwargs: Additional logger configuration

    Returns:
        UnifiedLogger instance
    """
    if name is None:
        # Get caller's module name
        import inspect
        frame = inspect.currentframe()
        if frame and frame.f_back:
            name = frame.f_back.f_globals.get('__name__', 'blncs')
        else:
            name = 'blncs'

    if name not in _loggers:
        # Get configuration from environment
        log_level = os.getenv('BLNCS_LOG_LEVEL', level)
        log_dir = os.getenv('BLNCS_LOG_DIR', kwargs.get('log_dir'))
        json_format = os.getenv('BLNCS_LOG_FORMAT', 'text').lower() == 'json'
        use_structlog = os.getenv('BLNCS_USE_STRUCTLOG', 'false').lower() in ['true', '1', 'yes']

        _loggers[name] = UnifiedLogger(
            name=name,
            level=log_level,
            log_dir=log_dir,
            json_format=json_format or kwargs.get('json_format', False),
            use_structlog=use_structlog or kwargs.get('use_structlog', False),
            **kwargs
        )

    return _loggers[name]


def configure_logging(
    level: Union[str, int] = "INFO",
    log_dir: Optional[str] = None,
    json_format: bool = False,
    use_structlog: bool = False
):
    """
    Configure global logging settings

    Args:
        level: Default log level
        log_dir: Directory for log files
        json_format: Use JSON formatting
        use_structlog: Use structlog if available
    """
    # Set environment variables for future loggers
    os.environ['BLNCS_LOG_LEVEL'] = str(level)
    if log_dir:
        os.environ['BLNCS_LOG_DIR'] = log_dir
    os.environ['BLNCS_LOG_FORMAT'] = 'json' if json_format else 'text'
    os.environ['BLNCS_USE_STRUCTLOG'] = 'true' if use_structlog else 'false'

    # Configure root logger
    root_logger = get_logger('blncs', level=level)
    root_logger.info("Logging configured", level=level, log_dir=log_dir)


    root_logger.info("Logging configured", level=level, log_dir=log_dir)


class LogManager:
    """
    Comprehensive log management system with rotation, compression, and analysis
    """

    def __init__(self, logs_dir: str = "logs"):
        self.logs_dir = Path(logs_dir)
        self.logs_dir.mkdir(exist_ok=True)
        self.log_configs: Dict[str, LogConfig] = {}
        self.rotation_tasks: Dict[str, asyncio.Task] = {}

        # Default log configurations
        self._setup_default_configs()

    def _setup_default_configs(self):
        """Setup default log configurations"""
        default_configs = {
            'blncs.log': LogConfig(
                file_path=str(self.logs_dir / 'blncs.log'),
                max_size_mb=50,
                backup_count=20,
                rotation_interval='daily',
                level='INFO'
            ),
            'access.log': LogConfig(
                file_path=str(self.logs_dir / 'access.log'),
                max_size_mb=100,
                backup_count=10,
                rotation_interval='weekly',
                level='INFO'
            ),
            'error.log': LogConfig(
                file_path=str(self.logs_dir / 'error.log'),
                max_size_mb=50,
                backup_count=30,
                rotation_interval='daily',
                level='ERROR'
            ),
            'audit.log': LogConfig(
                file_path=str(self.logs_dir / 'audit.log'),
                max_size_mb=200,
                backup_count=50,
                rotation_interval='monthly',
                level='INFO'
            )
        }

        self.log_configs.update(default_configs)

    def add_log_config(self, name: str, config: LogConfig):
        """Add or update log configuration"""
        self.log_configs[name] = config

    async def rotate_logs(self, config_name: Optional[str] = None) -> Dict[str, LogRotationResult]:
        """Rotate logs based on configuration"""
        results = {}

        configs_to_rotate = [config_name] if config_name else list(self.log_configs.keys())

        for name in configs_to_rotate:
            if name in self.log_configs:
                result = await self._rotate_single_log(name)
                results[name] = result

        return results

    async def _rotate_single_log(self, config_name: str) -> LogRotationResult:
        """Rotate a single log file"""
        config = self.log_configs[config_name]

        try:
            log_path = Path(config.file_path)
            if not log_path.exists():
                return LogRotationResult(success=True, error_message="Log file doesn't exist")

            # Get current size
            current_size = log_path.stat().st_size
            size_before = self._get_total_log_size(config_name)

            # Check if rotation is needed
            should_rotate = (
                current_size > config.max_size_mb * 1024 * 1024 or
                self._should_rotate_by_time(config)
            )

            if not should_rotate:
                return LogRotationResult(
                    success=True,
                    total_size_before=size_before,
                    total_size_after=size_before
                )

            # Perform rotation
            rotated_files = await self._perform_rotation(log_path, config)

            # Get new size
            size_after = self._get_total_log_size(config_name)

            return LogRotationResult(
                success=True,
                rotated_files=rotated_files,
                total_size_before=size_before,
                total_size_after=size_after
            )

        except Exception as e:
            return LogRotationResult(
                success=False,
                error_message=str(e)
            )

    def _should_rotate_by_time(self, config: LogConfig) -> bool:
        """Check if rotation is needed based on time interval"""
        if not config.rotation_interval:
            return False

        log_path = Path(config.file_path)

        # Check if main log file exists
        if not log_path.exists():
            return False

        # Check modification time
        mtime = log_path.stat().st_mtime
        now = time.time()

        if config.rotation_interval == 'daily':
            return (now - mtime) > 24 * 3600
        elif config.rotation_interval == 'weekly':
            return (now - mtime) > 7 * 24 * 3600
        elif config.rotation_interval == 'monthly':
            return (now - mtime) > 30 * 24 * 3600

        return False

    async def _perform_rotation(self, log_path: Path, config: LogConfig) -> List[str]:
        """Perform actual log rotation"""
        rotated_files = []

        try:
            # Close any open file handlers for this log
            logger_name = f"blncs.{Path(config.file_path).name}"
            log = logging.getLogger(logger_name)

            # Remove and re-add handlers to force rotation
            for handler in log.handlers[:]:
                if isinstance(handler, logging.handlers.RotatingFileHandler):
                    if handler.baseFilename == config.file_path:
                        log.removeHandler(handler)
                        handler.close()

            # Manually trigger rotation by renaming files
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

            for i in range(config.backup_count, 0, -1):
                old_file = log_path.with_suffix(f'.{i}')
                new_file = log_path.with_suffix(f'.{i+1}')

                if old_file.exists():
                    if i + 1 <= config.backup_count:
                        if new_file.exists():
                            new_file.unlink()  # Remove oldest backup
                        old_file.rename(new_file)

            # Move current log to .1
            backup_file = log_path.with_suffix('.1')
            if log_path.exists():
                log_path.rename(backup_file)
                rotated_files.append(str(backup_file))

        except Exception as e:
            logger.error(f"Log rotation failed for {log_path}: {e}")

        return rotated_files

    def _get_total_log_size(self, config_name: str) -> int:
        """Get total size of all log files for a configuration"""
        config = self.log_configs[config_name]
        log_path = Path(config.file_path)

        total_size = 0

        # Main log file
        if log_path.exists():
            total_size += log_path.stat().st_size

        # Backup files
        for i in range(1, config.backup_count + 1):
            backup_file = log_path.with_suffix(f'.{i}')
            if backup_file.exists():
                total_size += backup_file.stat().st_size

        return total_size

    def compress_old_logs(self, config_name: str, keep_uncompressed: int = 2) -> List[str]:
        """Compress old log files"""
        compressed_files = []
        config = self.log_configs[config_name]
        log_path = Path(config.file_path)

        # Compress files older than keep_uncompressed count
        files_to_compress = []
        for i in range(keep_uncompressed + 1, config.backup_count + 1):
            backup_file = log_path.with_suffix(f'.{i}')
            if backup_file.exists() and not str(backup_file).endswith('.gz'):
                files_to_compress.append(backup_file)

        for file_path in files_to_compress:
            try:
                compressed_path = file_path.with_suffix(f'.{file_path.suffix}.gz')

                # Compress file
                with open(file_path, 'rb') as f_in:
                    with gzip.open(compressed_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)

                # Remove original file
                file_path.unlink()
                compressed_files.append(str(compressed_path))

            except Exception as e:
                logger.warning(f"Failed to compress {file_path}: {e}")

        return compressed_files

    def get_log_statistics(self) -> Dict[str, Any]:
        """Get comprehensive log statistics"""
        stats = {
            'total_logs': len(self.log_configs),
            'total_size': 0,
            'log_details': {}
        }

        for name, config in self.log_configs.items():
            info = self.get_log_info(name)
            stats['log_details'][name] = info
            stats['total_size'] += info['total_size']

        return stats

    def get_log_info(self, config_name: str) -> Dict[str, Any]:
        """Get detailed information about a log configuration"""
        config = self.log_configs[config_name]
        log_path = Path(config.file_path)

        info = {
            'name': config_name,
            'file_path': config.file_path,
            'current_size': 0,
            'backup_files': [],
            'total_size': 0,
            'oldest_backup': None,
            'newest_backup': None
        }

        # Current log file
        if log_path.exists():
            stat = log_path.stat()
            info['current_size'] = stat.st_size
            info['total_size'] += stat.st_size

        # Backup files
        backup_info = []
        for i in range(1, config.backup_count + 1):
            backup_file = log_path.with_suffix(f'.{i}')
            if backup_file.exists():
                stat = backup_file.stat()
                backup_info.append({
                    'number': i,
                    'path': str(backup_file),
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                })
                info['total_size'] += stat.st_size

        info['backup_files'] = backup_info

        if backup_info:
            info['oldest_backup'] = min(backup_info, key=lambda x: x['modified'])['modified']
            info['newest_backup'] = max(backup_info, key=lambda x: x['modified'])['modified']

        return info

    def analyze_log_file(self, log_path: Union[str, Path], hours: int = 24) -> Dict[str, Any]:
        """Analyze log file and generate statistics"""
        log_path = Path(log_path)

        if not log_path.exists():
            return {'error': f'Log file does not exist: {log_path}'}

        analysis = {
            'file_info': {
                'path': str(log_path),
                'size': log_path.stat().st_size,
                'modified': datetime.fromtimestamp(log_path.stat().st_mtime, tz=timezone.utc)
            },
            'time_range': {
                'start': None,
                'end': None
            },
            'statistics': {
                'total_entries': 0,
                'level_counts': defaultdict(int),
                'logger_counts': defaultdict(int),
                'error_patterns': defaultdict(int),
                'hourly_distribution': defaultdict(int)
            },
            'top_errors': [],
            'recent_entries': []
        }

        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)

        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f):
                    line = line.strip()
                    if not line:
                        continue

                    # Parse log entry
                    entry = self._parse_log_entry(line)
                    if not entry:
                        continue

                    # Check time filter
                    if entry.get('timestamp') and entry['timestamp'] < cutoff_time:
                        continue

                    analysis['statistics']['total_entries'] += 1

                    # Update statistics
                    if 'level' in entry:
                        analysis['statistics']['level_counts'][entry['level']] += 1

                    if 'logger' in entry:
                        analysis['statistics']['logger_counts'][entry['logger']] += 1

                    # Update time range
                    if entry.get('timestamp'):
                        if analysis['time_range']['start'] is None or entry['timestamp'] < analysis['time_range']['start']:
                            analysis['time_range']['start'] = entry['timestamp']
                        if analysis['time_range']['end'] is None or entry['timestamp'] > analysis['time_range']['end']:
                            analysis['time_range']['end'] = entry['timestamp']

                        # Hourly distribution
                        hour_key = entry['timestamp'].strftime('%Y-%m-%d %H:00')
                        analysis['statistics']['hourly_distribution'][hour_key] += 1

                    # Error pattern detection
                    if entry.get('level') in ['ERROR', 'CRITICAL']:
                        error_msg = entry.get('message', '')[:100]  # First 100 chars
                        analysis['statistics']['error_patterns'][error_msg] += 1

                    # Keep recent entries (last 50)
                    if len(analysis['recent_entries']) < 50:
                        analysis['recent_entries'].append(entry)

            # Process top errors
            error_patterns = analysis['statistics']['error_patterns']
            analysis['top_errors'] = sorted(
                [{'pattern': pattern, 'count': count} for pattern, count in error_patterns.items()],
                key=lambda x: x['count'],
                reverse=True
            )[:10]

            # Convert defaultdict to regular dict for JSON serialization
            analysis['statistics']['level_counts'] = dict(analysis['statistics']['level_counts'])
            analysis['statistics']['logger_counts'] = dict(analysis['statistics']['logger_counts'])
            analysis['statistics']['error_patterns'] = dict(analysis['statistics']['error_patterns'])
            analysis['statistics']['hourly_distribution'] = dict(analysis['statistics']['hourly_distribution'])

            # Convert timestamps to ISO format
            if analysis['time_range']['start']:
                analysis['time_range']['start'] = analysis['time_range']['start'].isoformat()
            if analysis['time_range']['end']:
                analysis['time_range']['end'] = analysis['time_range']['end'].isoformat()

            analysis['file_info']['modified'] = analysis['file_info']['modified'].isoformat()

        except Exception as e:
            analysis['error'] = f'Failed to analyze log file: {str(e)}'

        return analysis

    def _parse_log_entry(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single log entry"""
        try:
            # Try JSON format first
            if line.strip().startswith('{'):
                data = json.loads(line)
                # Convert timestamp if present
                if 'timestamp' in data:
                    try:
                        data['timestamp'] = datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
                    except:
                        data['timestamp'] = datetime.now(timezone.utc)
                else:
                    data['timestamp'] = datetime.now(timezone.utc)
                return data

            # Try standard format parsing
            # Format: 2024-01-09 10:30:15,123 - logger.name - LEVEL - message
            pattern = r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:,\d{3})?)\s*-\s*([^-\s]+)\s*-\s*(\w+)\s*-\s*(.+)$'
            match = re.match(pattern, line)

            if match:
                timestamp_str, logger_name, level, message = match.groups()

                # Parse timestamp
                try:
                    # Handle different timestamp formats
                    if ',' in timestamp_str:
                        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f')
                    else:
                        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                    timestamp = timestamp.replace(tzinfo=timezone.utc)
                except:
                    timestamp = datetime.now(timezone.utc)

                return {
                    'timestamp': timestamp,
                    'logger': logger_name,
                    'level': level,
                    'message': message
                }

            # Fallback: create basic entry
            return {
                'timestamp': datetime.now(timezone.utc),
                'logger': 'unknown',
                'level': 'UNKNOWN',
                'message': line,
                'raw': True
            }

        except Exception:
            return None

    def generate_log_report(self, log_path: Union[str, Path], output_format: str = 'json') -> str:
        """Generate a comprehensive log analysis report"""
        analysis = self.analyze_log_file(log_path)

        if output_format.lower() == 'json':
            return json.dumps(analysis, indent=2, ensure_ascii=False, default=str)
        elif output_format.lower() == 'text':
            return self._format_log_report_text(analysis)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")

    def _format_log_report_text(self, analysis: Dict[str, Any]) -> str:
        """Format log analysis as human-readable text"""
        if 'error' in analysis:
            return f"Log Analysis Error: {analysis['error']}"

        lines = []
        lines.append("BLNCS Log Analysis Report")
        lines.append("=" * 50)

        # File info
        file_info = analysis['file_info']
        lines.append(f"Log File: {file_info['path']}")
        lines.append(f"File Size: {file_info['size']:,} bytes")
        lines.append(f"Last Modified: {file_info['modified']}")
        lines.append("")

        # Time range
        time_range = analysis['time_range']
        lines.append("Time Range:")
        lines.append(f"  Start: {time_range.get('start', 'N/A')}")
        lines.append(f"  End: {time_range.get('end', 'N/A')}")
        lines.append("")

        # Statistics
        stats = analysis['statistics']
        lines.append("Statistics:")
        lines.append(f"  Total Entries: {stats['total_entries']:,}")
        lines.append("  Level Distribution:")

        for level, count in sorted(stats['level_counts'].items()):
            lines.append(f"    {level}: {count:,}")

        lines.append("")
        lines.append("  Top Loggers:")

        for logger, count in sorted(stats['logger_counts'].items(), key=lambda x: x[1], reverse=True)[:5]:
            lines.append(f"    {logger}: {count:,}")

        # Top errors
        if analysis['top_errors']:
            lines.append("")
            lines.append("Top Error Patterns:")

            for i, error in enumerate(analysis['top_errors'][:5], 1):
                lines.append(f"  {i}. {error['pattern'][:60]}{'...' if len(error['pattern']) > 60 else ''}")
                lines.append(f"     Count: {error['count']:,}")

        lines.append("")
        lines.append("Recent Entries:")

        for entry in analysis['recent_entries'][-10:]:  # Last 10 entries
            timestamp = entry.get('timestamp', 'N/A')
            if isinstance(timestamp, datetime):
                timestamp = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            level = entry.get('level', 'UNKNOWN')
            logger = entry.get('logger', 'unknown')
            message = entry.get('message', '')[:80]

            lines.append(f"  [{timestamp}] {level} {logger}: {message}")

    def monitor_security_events(self, log_path: Union[str, Path], alert_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Monitor log file for security events"""
        log_path = Path(log_path)

        security_patterns = {
            'authentication_failure': [
                r'Authentication failed',
                r'Invalid credentials',
                r'Login attempt failed',
                r'Unauthorized access'
            ],
            'suspicious_activity': [
                r'Multiple failed attempts',
                r'Unusual access pattern',
                r'Security violation',
                r'Suspicious request'
            ],
            'system_compromise': [
                r'Root access detected',
                r'System integrity compromised',
                r'Backdoor detected',
                r'Malware detected'
            ],
            'data_breach': [
                r'Sensitive data exposed',
                r'Encryption key leaked',
                r'Configuration leaked',
                r'Database breach'
            ]
        }

        security_events = {category: [] for category in security_patterns.keys()}
        summary = {
            'total_events': 0,
            'categories': {},
            'critical_events': [],
            'timeline': []
        }

        if not log_path.exists():
            return {'error': f'Log file does not exist: {log_path}'}

        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f):
                    line = line.strip()
                    if not line:
                        continue

                    # Parse log entry
                    entry = self._parse_log_entry(line)
                    if not entry:
                        continue

                    # Check for security patterns
                    message = entry.get('message', '').lower()

                    for category, patterns in security_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern.lower(), message):
                                event = {
                                    'timestamp': entry.get('timestamp'),
                                    'level': entry.get('level'),
                                    'message': entry.get('message'),
                                    'logger': entry.get('logger'),
                                    'line_number': line_num + 1,
                                    'category': category,
                                    'pattern': pattern
                                }

                                security_events[category].append(event)
                                summary['total_events'] += 1

                                # Check if critical
                                if category in ['system_compromise', 'data_breach'] or entry.get('level') in ['CRITICAL', 'ERROR']:
                                    summary['critical_events'].append(event)

                                    # Trigger alert callback
                                    if alert_callback:
                                        try:
                                            alert_callback(event)
                                        except Exception as e:
                                            print(f"Security alert callback error: {e}")

                                break  # Only categorize once per line

            # Generate summary statistics
            for category, events in security_events.items():
                if events:
                    summary['categories'][category] = {
                        'count': len(events),
                        'latest_event': max(events, key=lambda x: x['timestamp']) if events else None
                    }

            # Generate timeline
            all_events = []
            for events in security_events.values():
                all_events.extend(events)

            all_events.sort(key=lambda x: x['timestamp'], reverse=True)
            summary['timeline'] = all_events[:20]  # Last 20 events

            # Convert timestamps for JSON serialization
            def convert_timestamps(obj):
                if isinstance(obj, dict):
                    return {k: convert_timestamps(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [convert_timestamps(item) for item in obj]
                elif isinstance(obj, datetime):
                    return obj.isoformat()
                else:
                    return obj

            return convert_timestamps(summary)

        except Exception as e:
            return {'error': f'Failed to monitor security events: {str(e)}'}


def get_log_manager() -> LogManager:
    """Get global log manager instance"""
    global _log_manager
    if _log_manager is None:
        _log_manager = LogManager()
    return _log_manager


__all__ = [
    'UnifiedLogger',
    'get_logger',
    'configure_logging',
    'ColoredFormatter',
    'JSONFormatter',
    'LogManager',
    'LogConfig',
    'LogRotationResult',
    'get_log_manager'
]