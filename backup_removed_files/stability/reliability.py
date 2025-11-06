"""
Stability and Reliability Module for BLNCS Enterprise
Provides comprehensive error recovery, health monitoring, graceful shutdown, and backup/restore capabilities
"""

import time
import threading
import signal
import sys
import os
import shutil
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Callable, Optional, Any
from contextlib import contextmanager
import sqlite3
import traceback
import psutil
import socket
import requests
from pathlib import Path

logger = logging.getLogger(__name__)

class HealthChecker:
    """Comprehensive health monitoring system"""

    def __init__(self):
        self.checks = {}
        self.last_check = {}
        self.lock = threading.Lock()

    def register_check(self, name: str, check_func: Callable[[], bool], interval: int = 30):
        """Register a health check function"""
        self.checks[name] = {
            'function': check_func,
            'interval': interval,
            'last_run': 0
        }

    def run_check(self, name: str) -> Dict[str, Any]:
        """Run a specific health check"""
        if name not in self.checks:
            return {'status': 'not_found', 'error': 'Check not registered'}

        check = self.checks[name]
        current_time = time.time()

        # Check if enough time has passed since last run
        if current_time - check['last_run'] < check['interval']:
            return self.last_check.get(name, {'status': 'skipped', 'reason': 'too_soon'})

        try:
            result = check['function']()
            check['last_run'] = current_time

            check_result = {
                'status': 'healthy' if result else 'unhealthy',
                'timestamp': current_time,
                'check_name': name
            }

            with self.lock:
                self.last_check[name] = check_result

            return check_result

        except Exception as e:
            error_result = {
                'status': 'error',
                'error': str(e),
                'timestamp': current_time,
                'check_name': name
            }

            with self.lock:
                self.last_check[name] = error_result

            return error_result

    def run_all_checks(self) -> Dict[str, Dict[str, Any]]:
        """Run all registered health checks"""
        results = {}
        for name in self.checks.keys():
            results[name] = self.run_check(name)
        return results

    def get_overall_health(self) -> Dict[str, Any]:
        """Get overall system health status"""
        results = self.run_all_checks()

        healthy_count = sum(1 for r in results.values() if r['status'] == 'healthy')
        total_count = len(results)

        return {
            'overall_status': 'healthy' if healthy_count == total_count else 'degraded' if healthy_count > 0 else 'unhealthy',
            'healthy_checks': healthy_count,
            'total_checks': total_count,
            'details': results
        }

class ErrorRecoveryManager:
    """Advanced error recovery and circuit breaker"""

    def __init__(self):
        self.failure_counts = {}
        self.circuit_states = {}  # 'closed', 'open', 'half_open'
        self.last_failure_time = {}
        self.recovery_functions = {}
        self.lock = threading.Lock()

    def register_service(self, service_name: str, recovery_func: Callable[[], bool]):
        """Register a service with its recovery function"""
        with self.lock:
            self.failure_counts[service_name] = 0
            self.circuit_states[service_name] = 'closed'
            self.recovery_functions[service_name] = recovery_func

    def record_success(self, service_name: str):
        """Record successful operation"""
        with self.lock:
            self.failure_counts[service_name] = 0
            self.circuit_states[service_name] = 'closed'

    def record_failure(self, service_name: str) -> bool:
        """Record failed operation and check if circuit should open"""
        with self.lock:
            self.failure_counts[service_name] += 1
            self.last_failure_time[service_name] = time.time()
            self.circuit_states[service_name] = 'open'

            # Check if we should attempt recovery
            if self.failure_counts[service_name] >= 3:
                return self._attempt_recovery(service_name)

            return False

    def _attempt_recovery(self, service_name: str) -> bool:
        """Attempt to recover a failed service"""
        recovery_func = self.recovery_functions.get(service_name)
        if not recovery_func:
            return False

        try:
            success = recovery_func()
            if success:
                logger.info(f"Successfully recovered service: {service_name}")
                self.record_success(service_name)
                return True
            else:
                logger.warning(f"Failed to recover service: {service_name}")
                return False
        except Exception as e:
            logger.error(f"Error during service recovery {service_name}: {e}")
            return False

    def is_circuit_open(self, service_name: str) -> bool:
        """Check if circuit breaker is open for service"""
        with self.lock:
            return self.circuit_states.get(service_name) == 'open'

class BackupManager:
    """Automated backup and restore system"""

    def __init__(self, backup_dir: str = "backups"):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(exist_ok=True)
        self.max_backups = 10

    def create_backup(self, db_path: str, backup_name: str = None) -> str:
        """Create a backup of database"""
        if not backup_name:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"backup_{timestamp}.db"

        backup_path = self.backup_dir / backup_name

        try:
            # Create backup using SQLite backup API
            source = sqlite3.connect(db_path)
            backup = sqlite3.connect(str(backup_path))

            source.backup(backup)
            backup.close()
            source.close()

            logger.info(f"Created backup: {backup_path}")

            # Cleanup old backups
            self._cleanup_old_backups()

            return str(backup_path)

        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            raise

    def restore_backup(self, backup_path: str, target_db_path: str) -> bool:
        """Restore database from backup"""
        try:
            # Create temporary connection to backup
            backup = sqlite3.connect(backup_path)
            target = sqlite3.connect(target_db_path)

            # Restore from backup
            backup.backup(target)

            target.close()
            backup.close()

            logger.info(f"Restored database from: {backup_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to restore backup: {e}")
            return False

    def list_backups(self) -> List[Dict[str, Any]]:
        """List available backups with metadata"""
        backups = []

        for backup_file in self.backup_dir.glob("*.db"):
            try:
                stat = backup_file.stat()
                backups.append({
                    'name': backup_file.name,
                    'path': str(backup_file),
                    'size_mb': stat.st_size / 1024 / 1024,
                    'created': datetime.fromtimestamp(stat.st_mtime),
                    'modified': datetime.fromtimestamp(stat.st_mtime)
                })
            except Exception as e:
                logger.warning(f"Error reading backup file {backup_file}: {e}")

        # Sort by creation time (newest first)
        backups.sort(key=lambda x: x['created'], reverse=True)
        return backups

    def _cleanup_old_backups(self):
        """Remove old backups keeping only the most recent ones"""
        backups = self.list_backups()

        if len(backups) > self.max_backups:
            to_remove = backups[self.max_backups:]

            for backup in to_remove:
                try:
                    Path(backup['path']).unlink()
                    logger.info(f"Removed old backup: {backup['name']}")
                except Exception as e:
                    logger.warning(f"Failed to remove old backup {backup['name']}: {e}")

class GracefulShutdown:
    """Graceful shutdown handling"""

    def __init__(self):
        self.shutdown_handlers = []
        self.shutdown_event = threading.Event()
        self.lock = threading.Lock()

    def register_handler(self, handler: Callable[[], None], priority: int = 50):
        """Register a shutdown handler with priority"""
        with self.lock:
            self.shutdown_handlers.append({
                'handler': handler,
                'priority': priority
            })
            # Sort by priority (lower number = higher priority)
            self.shutdown_handlers.sort(key=lambda x: x['priority'])

    def initiate_shutdown(self, signal_type: str = "manual"):
        """Initiate graceful shutdown"""
        logger.info(f"Initiating graceful shutdown: {signal_type}")

        # Set shutdown event
        self.shutdown_event.set()

        # Run shutdown handlers in priority order
        with self.lock:
            handlers = self.shutdown_handlers.copy()

        for handler_info in handlers:
            try:
                handler_info['handler']()
            except Exception as e:
                logger.error(f"Error in shutdown handler: {e}")

        logger.info("Graceful shutdown completed")

    def is_shutting_down(self) -> bool:
        """Check if system is shutting down"""
        return self.shutdown_event.is_set()

    def wait_for_shutdown(self, timeout: float = None):
        """Wait for shutdown signal"""
        self.shutdown_event.wait(timeout)

class SystemMonitor:
    """System resource monitoring"""

    def __init__(self):
        self.monitoring = True
        self.monitor_thread = None
        self.metrics = {
            'cpu_percent': [],
            'memory_percent': [],
            'disk_usage': [],
            'network_io': []
        }
        self.lock = threading.Lock()

    def start_monitoring(self, interval: int = 30):
        """Start system monitoring"""
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, args=(interval,))
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def stop_monitoring(self):
        """Stop system monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)

    def _monitor_loop(self, interval: int):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                # CPU usage
                cpu_percent = psutil.cpu_percent(interval=1)

                # Memory usage
                memory = psutil.virtual_memory()

                # Disk usage
                disk = psutil.disk_usage('/')

                # Network I/O
                network = psutil.net_io_counters()

                with self.lock:
                    self.metrics['cpu_percent'].append(cpu_percent)
                    self.metrics['memory_percent'].append(memory.percent)
                    self.metrics['disk_usage'].append(disk.percent)
                    self.metrics['network_io'].append({
                        'bytes_sent': network.bytes_sent,
                        'bytes_recv': network.bytes_recv
                    })

                    # Keep only last 1000 measurements
                    for key in self.metrics:
                        if len(self.metrics[key]) > 1000:
                            self.metrics[key] = self.metrics[key][-1000:]

            except Exception as e:
                logger.error(f"Error in system monitoring: {e}")

            time.sleep(interval)

    def get_system_metrics(self) -> Dict[str, Any]:
        """Get current system metrics"""
        with self.lock:
            current_metrics = {}
            for key, values in self.metrics.items():
                if values:
                    current_metrics[key] = {
                        'current': values[-1],
                        'avg': sum(values[-10:]) / min(10, len(values)) if values else 0,
                        'max': max(values) if values else 0,
                        'min': min(values) if values else 0
                    }

            return current_metrics

class DatabaseHealthChecker:
    """Database-specific health checks"""

    def __init__(self, db_path: str):
        self.db_path = db_path

    def check_database_health(self) -> bool:
        """Check database connectivity and basic operations"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Test basic operations
            cursor.execute("SELECT 1")
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1")

            conn.close()
            return True

        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False

    def check_database_integrity(self) -> bool:
        """Check database integrity"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("PRAGMA integrity_check")
            conn.close()
            return True

        except Exception as e:
            logger.error(f"Database integrity check failed: {e}")
            return False

    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Get table count
            cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
            table_count = cursor.fetchone()[0]

            # Get total size
            db_size = os.path.getsize(self.db_path)

            conn.close()

            return {
                'table_count': table_count,
                'size_bytes': db_size,
                'size_mb': db_size / 1024 / 1024
            }

        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
            return {}

# Global stability instances
health_checker = HealthChecker()
error_recovery = ErrorRecoveryManager()
backup_manager = BackupManager()
graceful_shutdown = GracefulShutdown()
system_monitor = SystemMonitor()

def init_stability_system(db_path: str = None):
    """Initialize stability systems"""
    if db_path:
        # Register database health checks
        db_checker = DatabaseHealthChecker(db_path)
        health_checker.register_check('database', db_checker.check_database_health)
        health_checker.register_check('database_integrity', db_checker.check_database_integrity)

        # Register backup manager
        global backup_manager
        backup_manager = BackupManager()

def setup_signal_handlers():
    """Setup signal handlers for graceful shutdown"""
    def signal_handler(signum, frame):
        signal_type = "SIGTERM" if signum == signal.SIGTERM else "SIGINT"
        graceful_shutdown.initiate_shutdown(signal_type)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

@contextmanager
def error_recovery_context(service_name: str):
    """Context manager for error recovery"""
    try:
        yield
        error_recovery.record_success(service_name)
    except Exception as e:
        logger.error(f"Error in {service_name}: {e}")
        if error_recovery.record_failure(service_name):
            logger.info(f"Service {service_name} recovered successfully")
        else:
            logger.error(f"Failed to recover service {service_name}")

def health_check_endpoint():
    """Health check endpoint for monitoring systems"""
    try:
        health = health_checker.get_overall_health()
        system_metrics = system_monitor.get_system_metrics()

        response = {
            'status': health['overall_status'],
            'timestamp': time.time(),
            'health_checks': health['details'],
            'system_metrics': system_metrics
        }

        return response

    except Exception as e:
        logger.error(f"Health check endpoint error: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': time.time()
        }
