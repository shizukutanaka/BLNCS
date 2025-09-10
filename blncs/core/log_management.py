"""
Log Management and Rotation System
Automatic log rotation, compression, and cleanup for BLNCS.
"""

import os
import gzip
import time
import threading
import shutil
from typing import Dict, Any, Optional, List, Callable
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import logging
import logging.handlers
import re

from .logger import get_logger
from .config_manager import get_config_manager

logger = get_logger(__name__)

class LogLevel(Enum):
    """Log levels for filtering."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

@dataclass
class LogRotationConfig:
    """Configuration for log rotation."""
    log_file: str
    max_size_mb: int = 10
    max_files: int = 5
    compress: bool = True
    max_age_days: int = 30
    enabled: bool = True

@dataclass
class LogCleanupStats:
    """Statistics from log cleanup operation."""
    files_cleaned: int = 0
    space_freed_mb: float = 0.0
    files_compressed: int = 0
    compression_ratio: float = 0.0
    errors: List[str] = field(default_factory=list)

class LogManager:
    """Comprehensive log management system."""
    
    def __init__(self, base_log_dir: str = "logs"):
        """Initialize log manager."""
        self.base_log_dir = Path(base_log_dir)
        self.base_log_dir.mkdir(exist_ok=True, parents=True)
        
        self.configs: Dict[str, LogRotationConfig] = {}
        self.running = False
        self.cleanup_thread: Optional[threading.Thread] = None
        
        self.logger = get_logger(__name__)
        self.config_manager = get_config_manager()
        
        # Setup default log rotation configs
        self._setup_default_configs()
        
        # Statistics
        self.last_cleanup = datetime.now()
        self.cleanup_stats: List[LogCleanupStats] = []
    
    def _setup_default_configs(self):
        """Setup default log rotation configurations."""
        default_configs = [
            LogRotationConfig(
                log_file="blncs.log",
                max_size_mb=50,
                max_files=10,
                max_age_days=30
            ),
            LogRotationConfig(
                log_file="error.log",
                max_size_mb=20,
                max_files=20,
                max_age_days=90  # Keep errors longer
            ),
            LogRotationConfig(
                log_file="lightning.log",
                max_size_mb=30,
                max_files=7,
                max_age_days=14
            ),
            LogRotationConfig(
                log_file="performance.log",
                max_size_mb=100,
                max_files=5,
                max_age_days=7
            ),
            LogRotationConfig(
                log_file="security.log",
                max_size_mb=25,
                max_files=30,
                max_age_days=180  # Keep security logs longer
            )
        ]
        
        for config in default_configs:
            self.configs[config.log_file] = config
    
    def add_log_config(self, config: LogRotationConfig):
        """Add log rotation configuration."""
        self.configs[config.log_file] = config
        self.logger.info(f"Added log rotation config for {config.log_file}")
    
    def rotate_log(self, log_file: str) -> bool:
        """Rotate a specific log file."""
        if log_file not in self.configs:
            return False
        
        config = self.configs[log_file]
        log_path = self.base_log_dir / log_file
        
        if not log_path.exists():
            return True  # Nothing to rotate
        
        try:
            # Check if rotation is needed
            file_size_mb = log_path.stat().st_size / (1024 * 1024)
            
            if file_size_mb < config.max_size_mb:
                return True  # No rotation needed
            
            # Perform rotation
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            rotated_name = f"{log_file}.{timestamp}"
            
            if config.compress:
                rotated_name += ".gz"
            
            rotated_path = self.base_log_dir / rotated_name
            
            if config.compress:
                # Compress while rotating
                with open(log_path, 'rb') as f_in:
                    with gzip.open(rotated_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                
                # Remove original
                log_path.unlink()
            else:
                # Simple rename
                log_path.rename(rotated_path)
            
            # Create new log file
            log_path.touch()
            
            self.logger.info(f"Rotated log file: {log_file} -> {rotated_name}")
            
            # Clean up old rotated files
            self._cleanup_rotated_files(log_file, config)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to rotate log {log_file}: {e}")
            return False
    
    def _cleanup_rotated_files(self, log_file: str, config: LogRotationConfig):
        """Clean up old rotated log files."""
        try:
            # Find all rotated files for this log
            pattern = f"{log_file}.*"
            rotated_files = list(self.base_log_dir.glob(pattern))
            
            # Filter out the main log file
            rotated_files = [f for f in rotated_files if f.name != log_file]
            
            # Sort by modification time (newest first)
            rotated_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            
            # Remove files exceeding max_files limit
            if len(rotated_files) > config.max_files:
                for old_file in rotated_files[config.max_files:]:
                    old_file.unlink()
                    self.logger.debug(f"Removed old rotated log: {old_file.name}")
            
            # Remove files older than max_age_days
            cutoff_time = datetime.now() - timedelta(days=config.max_age_days)
            cutoff_timestamp = cutoff_time.timestamp()
            
            for old_file in rotated_files:
                if old_file.stat().st_mtime < cutoff_timestamp:
                    old_file.unlink()
                    self.logger.debug(f"Removed expired log: {old_file.name}")
                    
        except Exception as e:
            self.logger.error(f"Failed to cleanup rotated files for {log_file}: {e}")
    
    def compress_old_logs(self, days_old: int = 1) -> LogCleanupStats:
        """Compress log files older than specified days."""
        stats = LogCleanupStats()
        cutoff_time = datetime.now() - timedelta(days=days_old)
        cutoff_timestamp = cutoff_time.timestamp()
        
        try:
            # Find uncompressed log files
            for log_file in self.base_log_dir.glob("*.log*"):
                if log_file.suffix == '.gz':
                    continue  # Already compressed
                
                file_stat = log_file.stat()
                if file_stat.st_mtime < cutoff_timestamp:
                    try:
                        # Compress the file
                        compressed_path = log_file.with_suffix(log_file.suffix + '.gz')
                        
                        with open(log_file, 'rb') as f_in:
                            with gzip.open(compressed_path, 'wb') as f_out:
                                shutil.copyfileobj(f_in, f_out)
                        
                        # Calculate compression ratio
                        original_size = file_stat.st_size
                        compressed_size = compressed_path.stat().st_size
                        
                        if original_size > 0:
                            ratio = compressed_size / original_size
                            stats.compression_ratio += ratio
                        
                        # Remove original
                        log_file.unlink()
                        
                        stats.files_compressed += 1
                        stats.space_freed_mb += (original_size - compressed_size) / (1024 * 1024)
                        
                        self.logger.debug(f"Compressed log file: {log_file.name}")
                        
                    except Exception as e:
                        error_msg = f"Failed to compress {log_file.name}: {e}"
                        stats.errors.append(error_msg)
                        self.logger.error(error_msg)
            
            # Calculate average compression ratio
            if stats.files_compressed > 0:
                stats.compression_ratio /= stats.files_compressed
                
        except Exception as e:
            error_msg = f"Error during log compression: {e}"
            stats.errors.append(error_msg)
            self.logger.error(error_msg)
        
        return stats
    
    def cleanup_logs(self, max_age_days: int = 30) -> LogCleanupStats:
        """Clean up old log files."""
        stats = LogCleanupStats()
        cutoff_time = datetime.now() - timedelta(days=max_age_days)
        cutoff_timestamp = cutoff_time.timestamp()
        
        try:
            for log_file in self.base_log_dir.rglob("*"):
                if not log_file.is_file():
                    continue
                
                file_stat = log_file.stat()
                if file_stat.st_mtime < cutoff_timestamp:
                    try:
                        file_size_mb = file_stat.st_size / (1024 * 1024)
                        log_file.unlink()
                        
                        stats.files_cleaned += 1
                        stats.space_freed_mb += file_size_mb
                        
                        self.logger.debug(f"Cleaned up old log: {log_file.name}")
                        
                    except Exception as e:
                        error_msg = f"Failed to delete {log_file.name}: {e}"
                        stats.errors.append(error_msg)
                        self.logger.error(error_msg)
                        
        except Exception as e:
            error_msg = f"Error during log cleanup: {e}"
            stats.errors.append(error_msg)
            self.logger.error(error_msg)
        
        return stats
    
    def rotate_all_logs(self) -> Dict[str, bool]:
        """Rotate all configured log files."""
        results = {}
        
        for log_file in self.configs:
            if self.configs[log_file].enabled:
                results[log_file] = self.rotate_log(log_file)
        
        return results
    
    def comprehensive_cleanup(self) -> LogCleanupStats:
        """Perform comprehensive log maintenance."""
        total_stats = LogCleanupStats()
        
        # Rotate logs that need it
        rotation_results = self.rotate_all_logs()
        successful_rotations = sum(1 for success in rotation_results.values() if success)
        
        # Compress old logs
        compression_stats = self.compress_old_logs(days_old=1)
        
        # Clean up very old logs
        cleanup_stats = self.cleanup_logs(max_age_days=90)
        
        # Combine statistics
        total_stats.files_compressed = compression_stats.files_compressed
        total_stats.files_cleaned = cleanup_stats.files_cleaned
        total_stats.space_freed_mb = compression_stats.space_freed_mb + cleanup_stats.space_freed_mb
        total_stats.compression_ratio = compression_stats.compression_ratio
        total_stats.errors.extend(compression_stats.errors)
        total_stats.errors.extend(cleanup_stats.errors)
        
        # Update statistics
        self.cleanup_stats.append(total_stats)
        self.last_cleanup = datetime.now()
        
        if len(self.cleanup_stats) > 30:  # Keep last 30 cleanup runs
            self.cleanup_stats = self.cleanup_stats[-30:]
        
        self.logger.info(
            f"Log maintenance completed: {successful_rotations} rotations, "
            f"{total_stats.files_compressed} compressed, {total_stats.files_cleaned} cleaned, "
            f"{total_stats.space_freed_mb:.2f}MB freed"
        )
        
        return total_stats
    
    def start_automatic_cleanup(self, interval_hours: int = 24):
        """Start automatic log cleanup thread."""
        if self.running:
            return
        
        self.running = True
        
        def cleanup_loop():
            while self.running:
                try:
                    self.comprehensive_cleanup()
                    
                    # Sleep for the specified interval
                    for _ in range(interval_hours * 3600):
                        if not self.running:
                            break
                        time.sleep(1)
                        
                except Exception as e:
                    self.logger.error(f"Error in automatic cleanup: {e}")
                    time.sleep(3600)  # Wait 1 hour before retrying
        
        self.cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        self.cleanup_thread.start()
        
        self.logger.info(f"Started automatic log cleanup (every {interval_hours} hours)")
    
    def stop_automatic_cleanup(self):
        """Stop automatic log cleanup."""
        if not self.running:
            return
        
        self.running = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5)
        
        self.logger.info("Stopped automatic log cleanup")
    
    def get_log_statistics(self) -> Dict[str, Any]:
        """Get comprehensive log statistics."""
        try:
            total_size = 0
            file_count = 0
            compressed_count = 0
            log_files = {}
            
            for log_file in self.base_log_dir.rglob("*"):
                if log_file.is_file():
                    size = log_file.stat().st_size
                    total_size += size
                    file_count += 1
                    
                    if log_file.suffix == '.gz':
                        compressed_count += 1
                    
                    log_files[str(log_file.relative_to(self.base_log_dir))] = {
                        "size_mb": size / (1024 * 1024),
                        "compressed": log_file.suffix == '.gz',
                        "modified": datetime.fromtimestamp(log_file.stat().st_mtime).isoformat()
                    }
            
            recent_stats = self.cleanup_stats[-1] if self.cleanup_stats else None
            
            return {
                "total_size_mb": total_size / (1024 * 1024),
                "total_files": file_count,
                "compressed_files": compressed_count,
                "compression_ratio": compressed_count / file_count if file_count > 0 else 0,
                "configured_logs": len(self.configs),
                "enabled_logs": sum(1 for c in self.configs.values() if c.enabled),
                "last_cleanup": self.last_cleanup.isoformat(),
                "automatic_cleanup_running": self.running,
                "recent_cleanup_stats": {
                    "files_cleaned": recent_stats.files_cleaned if recent_stats else 0,
                    "space_freed_mb": recent_stats.space_freed_mb if recent_stats else 0,
                    "files_compressed": recent_stats.files_compressed if recent_stats else 0,
                    "errors": len(recent_stats.errors) if recent_stats else 0
                } if recent_stats else None,
                "log_files": log_files
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get log statistics: {e}")
            return {"error": str(e)}
    
    def setup_structured_logging(self, app_name: str = "blncs"):
        """Setup structured logging with rotation."""
        try:
            # Create formatters
            detailed_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s - '
                '[%(filename)s:%(lineno)d] - PID:%(process)d'
            )
            
            simple_formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            
            # Setup rotating file handlers for different log levels
            handlers = []
            
            # Main application log
            main_handler = logging.handlers.RotatingFileHandler(
                self.base_log_dir / "blncs.log",
                maxBytes=50 * 1024 * 1024,  # 50MB
                backupCount=10,
                encoding='utf-8'
            )
            main_handler.setFormatter(detailed_formatter)
            main_handler.setLevel(logging.INFO)
            handlers.append(main_handler)
            
            # Error log
            error_handler = logging.handlers.RotatingFileHandler(
                self.base_log_dir / "error.log", 
                maxBytes=20 * 1024 * 1024,  # 20MB
                backupCount=20,
                encoding='utf-8'
            )
            error_handler.setFormatter(detailed_formatter)
            error_handler.setLevel(logging.ERROR)
            handlers.append(error_handler)
            
            # Configure root logger
            root_logger = logging.getLogger()
            root_logger.setLevel(logging.INFO)
            
            # Remove existing handlers
            for handler in root_logger.handlers[:]:
                root_logger.removeHandler(handler)
            
            # Add new handlers
            for handler in handlers:
                root_logger.addHandler(handler)
            
            self.logger.info("Structured logging setup completed")
            
        except Exception as e:
            print(f"Failed to setup structured logging: {e}")

# Global log manager instance
_log_manager: Optional[LogManager] = None
_log_lock = threading.Lock()

def get_log_manager() -> LogManager:
    """Get global log manager instance."""
    global _log_manager
    if _log_manager is None:
        with _log_lock:
            if _log_manager is None:
                config = get_config_manager()
                log_dir = config.get('logging.directory', 'logs')
                _log_manager = LogManager(log_dir)
    return _log_manager

if __name__ == "__main__":
    # Test log management
    log_mgr = get_log_manager()
    
    # Setup structured logging
    log_mgr.setup_structured_logging()
    
    # Test logging
    test_logger = logging.getLogger("test")
    test_logger.info("Testing log management system")
    test_logger.error("Testing error logging")
    
    # Get statistics
    stats = log_mgr.get_log_statistics()
    print(f"Log statistics: {json.dumps(stats, indent=2)}")
    
    # Perform cleanup
    cleanup_stats = log_mgr.comprehensive_cleanup()
    print(f"Cleanup completed: {cleanup_stats.files_cleaned} files cleaned")
    
    # Start automatic cleanup
    log_mgr.start_automatic_cleanup(interval_hours=1)
    print("Automatic cleanup started")
    
    time.sleep(2)
    log_mgr.stop_automatic_cleanup()