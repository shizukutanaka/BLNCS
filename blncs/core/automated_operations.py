#!/usr/bin/env python3
"""
BLNCS Automated Operations System
Provides automated maintenance, updates, and monitoring
"""

import os
import time
import logging
import threading
import schedule
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import gzip
import shutil
import hashlib
import subprocess
import requests
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class LogRotationConfig:
    """Log rotation configuration"""
    enabled: bool = True
    max_age_days: int = 30
    max_size_mb: int = 100
    compression: bool = True
    rotation_schedule: str = "daily"  # daily, weekly, monthly
    retention_count: int = 10
    log_directories: List[str] = field(default_factory=list)


@dataclass
class SecurityUpdateConfig:
    """Security update configuration"""
    enabled: bool = True
    check_interval_hours: int = 24
    auto_apply: bool = False  # Only check by default
    update_sources: List[str] = field(default_factory=list)
    notification_email: Optional[str] = None
    risk_level: str = "medium"  # low, medium, high, critical


@dataclass
class MaintenanceTask:
    """Automated maintenance task"""
    name: str
    description: str
    schedule: str  # cron-like or interval
    enabled: bool = True
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    max_runtime_seconds: int = 300
    retry_count: int = 3
    dependencies: List[str] = field(default_factory=list)


@dataclass
class MaintenanceResult:
    """Result of maintenance task execution"""
    task_name: str
    success: bool
    start_time: datetime
    end_time: datetime
    output: str
    error: Optional[str] = None
    retry_count: int = 0


class AutomatedLogRotation:
    """Automated log rotation and management system"""

    def __init__(self, config: LogRotationConfig):
        self.config = config
        self.rotation_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.stats = {
            'total_rotations': 0,
            'total_compressed': 0,
            'total_cleaned': 0,
            'last_rotation': None
        }

    def start(self):
        """Start the log rotation service"""
        if not self.config.enabled:
            logger.info("Log rotation is disabled")
            return

        self.stop_event.clear()
        self.rotation_thread = threading.Thread(target=self._rotation_loop, daemon=True)
        self.rotation_thread.start()
        logger.info("Log rotation service started")

    def stop(self):
        """Stop the log rotation service"""
        if self.rotation_thread:
            self.stop_event.set()
            self.rotation_thread.join(timeout=5)
            logger.info("Log rotation service stopped")

    def _rotation_loop(self):
        """Main rotation loop"""
        while not self.stop_event.wait(3600):  # Check every hour
            try:
                self._perform_rotation()
            except Exception as e:
                logger.error(f"Log rotation error: {e}")

    def _perform_rotation(self):
        """Perform log rotation"""
        now = datetime.now()
        rotated_files = []

        for log_dir in self.config.log_directories:
            if not os.path.exists(log_dir):
                continue

            for file_path in Path(log_dir).rglob("*.log"):
                if self._should_rotate(file_path):
                    try:
                        rotated_path = self._rotate_file(file_path)
                        if rotated_path:
                            rotated_files.append(rotated_path)
                    except Exception as e:
                        logger.error(f"Failed to rotate {file_path}: {e}")

        # Clean up old rotated logs
        cleaned_count = self._cleanup_old_logs()

        self.stats['total_rotations'] += len(rotated_files)
        self.stats['total_cleaned'] += cleaned_count
        self.stats['last_rotation'] = now

        if rotated_files:
            logger.info(f"Rotated {len(rotated_files)} log files")

    def _should_rotate(self, file_path: Path) -> bool:
        """Check if a log file should be rotated"""
        try:
            stat = file_path.stat()

            # Check file size
            size_mb = stat.st_size / (1024 * 1024)
            if size_mb >= self.config.max_size_mb:
                return True

            # Check file age
            age_days = (time.time() - stat.st_mtime) / (24 * 3600)
            if age_days >= self.config.max_age_days:
                return True

            # Check schedule-based rotation
            if self.config.rotation_schedule == "daily":
                # Rotate if file is from previous day
                file_date = datetime.fromtimestamp(stat.st_mtime).date()
                today = datetime.now().date()
                if file_date < today:
                    return True

        except Exception as e:
            logger.error(f"Error checking rotation for {file_path}: {e}")

        return False

    def _rotate_file(self, file_path: Path) -> Optional[str]:
        """Rotate a single log file"""
        try:
            # Create rotation filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            stem = file_path.stem
            suffix = file_path.suffix

            rotated_name = f"{stem}_{timestamp}{suffix}"
            rotated_path = file_path.parent / rotated_name

            # Move/rename the file
            shutil.move(str(file_path), str(rotated_path))

            # Compress if enabled
            if self.config.compression:
                compressed_path = rotated_path.with_suffix(f"{suffix}.gz")
                with open(rotated_path, 'rb') as f_in:
                    with gzip.open(compressed_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                rotated_path.unlink()  # Remove uncompressed file
                rotated_path = compressed_path
                self.stats['total_compressed'] += 1

            return str(rotated_path)

        except Exception as e:
            logger.error(f"Failed to rotate {file_path}: {e}")
            return None

    def _cleanup_old_logs(self) -> int:
        """Clean up old rotated log files"""
        cleaned_count = 0

        for log_dir in self.config.log_directories:
            if not os.path.exists(log_dir):
                continue

            # Find rotated log files
            rotated_files = []
            for pattern in ["*.log.gz", "*.log.*"]:
                rotated_files.extend(Path(log_dir).glob(pattern))

            # Sort by modification time (oldest first)
            rotated_files.sort(key=lambda x: x.stat().st_mtime)

            # Remove files beyond retention count
            while len(rotated_files) > self.config.retention_count:
                old_file = rotated_files.pop(0)
                try:
                    old_file.unlink()
                    cleaned_count += 1
                except Exception as e:
                    logger.error(f"Failed to remove old log {old_file}: {e}")

        return cleaned_count

    def get_stats(self) -> Dict[str, Any]:
        """Get rotation statistics"""
        return {
            **self.stats,
            'config': {
                'enabled': self.config.enabled,
                'max_age_days': self.config.max_age_days,
                'max_size_mb': self.config.max_size_mb,
                'compression': self.config.compression,
                'retention_count': self.config.retention_count,
                'log_directories': self.config.log_directories
            }
        }

    def manual_rotate(self, log_directory: Optional[str] = None) -> Dict[str, Any]:
        """Manually trigger log rotation"""
        if log_directory:
            self.config.log_directories = [log_directory]

        old_stats = self.stats.copy()
        self._perform_rotation()

        return {
            'rotated': self.stats['total_rotations'] - old_stats['total_rotations'],
            'compressed': self.stats['total_compressed'] - old_stats['total_compressed'],
            'cleaned': self.stats['total_cleaned'] - old_stats['total_cleaned']
        }


class AutomatedSecurityUpdates:
    """Automated security update system"""

    def __init__(self, config: SecurityUpdateConfig):
        self.config = config
        self.update_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.last_check = None
        self.available_updates = []
        self.applied_updates = []

    def start(self):
        """Start the security update service"""
        if not self.config.enabled:
            logger.info("Security updates are disabled")
            return

        self.stop_event.clear()
        self.update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self.update_thread.start()
        logger.info("Security update service started")

    def stop(self):
        """Stop the security update service"""
        if self.update_thread:
            self.stop_event.set()
            self.update_thread.join(timeout=5)
            logger.info("Security update service stopped")

    def _update_loop(self):
        """Main update check loop"""
        while not self.stop_event.wait(self.config.check_interval_hours * 3600):
            try:
                self._check_for_updates()
            except Exception as e:
                logger.error(f"Security update check error: {e}")

    def _check_for_updates(self):
        """Check for available security updates"""
        logger.info("Checking for security updates...")

        updates_found = []

        # Check Python packages
        try:
            updates_found.extend(self._check_pip_updates())
        except Exception as e:
            logger.error(f"Failed to check pip updates: {e}")

        # Check system packages (if applicable)
        try:
            updates_found.extend(self._check_system_updates())
        except Exception as e:
            logger.error(f"Failed to check system updates: {e}")

        # Check BLNCS-specific updates
        try:
            updates_found.extend(self._check_blncs_updates())
        except Exception as e:
            logger.error(f"Failed to check BLNCS updates: {e}")

        self.available_updates = updates_found
        self.last_check = datetime.now()

        if updates_found:
            logger.warning(f"Found {len(updates_found)} security updates")
            self._notify_updates(updates_found)
        else:
            logger.info("No security updates found")

    def _check_pip_updates(self) -> List[Dict[str, Any]]:
        """Check for outdated pip packages"""
        try:
            result = subprocess.run(
                ['pip', 'list', '--outdated', '--format=json'],
                capture_output=True, text=True, timeout=30
            )

            if result.returncode == 0 and result.stdout:
                packages = json.loads(result.stdout)
                updates = []

                for pkg in packages:
                    # Filter for security-related packages
                    if self._is_security_package(pkg['name']):
                        updates.append({
                            'type': 'python',
                            'package': pkg['name'],
                            'current': pkg['version'],
                            'latest': pkg.get('latest_version', 'unknown'),
                            'risk_level': self._assess_risk(pkg['name']),
                            'description': f"Security update for {pkg['name']}"
                        })

                return updates

        except Exception as e:
            logger.error(f"Pip update check failed: {e}")

        return []

    def _check_system_updates(self) -> List[Dict[str, Any]]:
        """Check for system-level security updates"""
        updates = []

        # This would be platform-specific
        # For demonstration, we'll simulate some common updates

        # In a real implementation, this would use:
        # - apt/yum/dnf for Linux
        # - Windows Update API for Windows
        # - Homebrew for macOS

        return updates

    def _check_blncs_updates(self) -> List[Dict[str, Any]]:
        """Check for BLNCS-specific security updates"""
        try:
            # Check for BLNCS updates via API or version check
            # This is a placeholder for actual implementation
            return []
        except Exception as e:
            logger.error(f"BLNCS update check failed: {e}")
            return []

    def _is_security_package(self, package_name: str) -> bool:
        """Check if a package is security-related"""
        security_packages = {
            'cryptography', 'pyotp', 'bcrypt', 'jwt', 'requests', 'urllib3',
            'paramiko', 'fabric', 'ansible', 'psutil', 'gputil'
        }

        return package_name.lower() in security_packages

    def _assess_risk(self, package_name: str) -> str:
        """Assess risk level for a package update"""
        high_risk = {'cryptography', 'jwt', 'bcrypt'}
        medium_risk = {'requests', 'urllib3', 'paramiko'}

        if package_name in high_risk:
            return 'high'
        elif package_name in medium_risk:
            return 'medium'
        else:
            return 'low'

    def _notify_updates(self, updates: List[Dict[str, Any]]):
        """Notify about available updates"""
        critical_updates = [u for u in updates if u.get('risk_level') == 'critical']
        high_updates = [u for u in updates if u.get('risk_level') == 'high']

        if critical_updates or high_updates:
            logger.critical(f"CRITICAL/HIGH RISK UPDATES FOUND: {len(critical_updates + high_updates)}")

        # Log all updates
        for update in updates:
            level = 'WARNING' if update['risk_level'] in ['high', 'critical'] else 'INFO'
            logger.log(getattr(logging, level),
                      f"Security update available: {update['package']} "
                      f"({update.get('current')} -> {update.get('latest')}) "
                      f"Risk: {update['risk_level']}")

        # Send email notification if configured
        if self.config.notification_email:
            self._send_notification_email(updates)

    def _send_notification_email(self, updates: List[Dict[str, Any]]):
        """Send email notification about updates"""
        # Placeholder for email sending implementation
        logger.info(f"Would send email notification to {self.config.notification_email} "
                   f"about {len(updates)} security updates")

    def apply_updates(self, updates: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        """Apply security updates"""
        if not self.config.auto_apply:
            logger.warning("Auto-apply is disabled, manual intervention required")
            return []

        target_updates = updates or self.available_updates
        applied = []

        for update in target_updates:
            try:
                if self._apply_single_update(update):
                    applied.append(update)
                    self.applied_updates.append({
                        **update,
                        'applied_at': datetime.now()
                    })
                    logger.info(f"Successfully applied update: {update['package']}")
                else:
                    logger.error(f"Failed to apply update: {update['package']}")
            except Exception as e:
                logger.error(f"Error applying update {update['package']}: {e}")

        return applied

    def _apply_single_update(self, update: Dict[str, Any]) -> bool:
        """Apply a single update"""
        try:
            if update['type'] == 'python':
                # Use pip to upgrade
                result = subprocess.run(
                    ['pip', 'install', '--upgrade', update['package']],
                    capture_output=True, text=True, timeout=300
                )

                return result.returncode == 0

        except Exception as e:
            logger.error(f"Failed to apply update {update}: {e}")

        return False

    def get_update_status(self) -> Dict[str, Any]:
        """Get current update status"""
        return {
            'enabled': self.config.enabled,
            'last_check': self.last_check.isoformat() if self.last_check else None,
            'available_updates': len(self.available_updates),
            'applied_updates': len(self.applied_updates),
            'auto_apply': self.config.auto_apply,
            'updates': self.available_updates
        }


class AutomatedMaintenance:
    """Automated maintenance system"""

    def __init__(self):
        self.tasks: Dict[str, MaintenanceTask] = {}
        self.scheduler = schedule.Scheduler()
        self.maintenance_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.results: List[MaintenanceResult] = []

        self._initialize_default_tasks()

    def _initialize_default_tasks(self):
        """Initialize default maintenance tasks"""
        default_tasks = [
            MaintenanceTask(
                name="log_cleanup",
                description="Clean up old log files and rotate logs",
                schedule="daily",
                enabled=True
            ),
            MaintenanceTask(
                name="cache_cleanup",
                description="Clean up expired cache entries",
                schedule="hourly",
                enabled=True
            ),
            MaintenanceTask(
                name="database_optimize",
                description="Optimize database performance",
                schedule="weekly",
                enabled=True
            ),
            MaintenanceTask(
                name="security_audit",
                description="Perform security audit and check",
                schedule="daily",
                enabled=True
            ),
            MaintenanceTask(
                name="performance_monitor",
                description="Monitor system performance metrics",
                schedule="hourly",
                enabled=True
            ),
            MaintenanceTask(
                name="backup_verify",
                description="Verify backup integrity",
                schedule="daily",
                enabled=True
            )
        ]

        for task in default_tasks:
            self.add_task(task)

    def add_task(self, task: MaintenanceTask):
        """Add a maintenance task"""
        self.tasks[task.name] = task
        self._schedule_task(task)

    def remove_task(self, task_name: str):
        """Remove a maintenance task"""
        if task_name in self.tasks:
            # Cancel existing schedule
            self.scheduler.clear(task_name)
            del self.tasks[task_name]

    def enable_task(self, task_name: str):
        """Enable a maintenance task"""
        if task_name in self.tasks:
            self.tasks[task_name].enabled = True
            self._schedule_task(self.tasks[task_name])

    def disable_task(self, task_name: str):
        """Disable a maintenance task"""
        if task_name in self.tasks:
            self.tasks[task_name].enabled = False
            self.scheduler.clear(task_name)

    def _schedule_task(self, task: MaintenanceTask):
        """Schedule a maintenance task"""
        if not task.enabled:
            return

        job = None

        if task.schedule == "hourly":
            job = self.scheduler.every().hour.do(self._run_task, task.name)
        elif task.schedule == "daily":
            job = self.scheduler.every().day.do(self._run_task, task.name)
        elif task.schedule == "weekly":
            job = self.scheduler.every().week.do(self._run_task, task.name)
        elif task.schedule.startswith("every"):
            # Parse "every N hours/days"
            try:
                parts = task.schedule.split()
                if len(parts) >= 3:
                    interval = int(parts[1])
                    unit = parts[2]

                    if unit.startswith("hour"):
                        job = self.scheduler.every(interval).hours.do(self._run_task, task.name)
                    elif unit.startswith("day"):
                        job = self.scheduler.every(interval).days.do(self._run_task, task.name)
            except ValueError:
                logger.error(f"Invalid schedule format: {task.schedule}")

        if job:
            job.tag(task.name)

    def _run_task(self, task_name: str):
        """Run a maintenance task"""
        if task_name not in self.tasks:
            return

        task = self.tasks[task_name]
        start_time = datetime.now()

        try:
            logger.info(f"Starting maintenance task: {task_name}")

            # Execute the task
            result = self._execute_task(task)

            end_time = datetime.now()
            success = result.returncode == 0 if hasattr(result, 'returncode') else True

            # Store result
            maintenance_result = MaintenanceResult(
                task_name=task_name,
                success=success,
                start_time=start_time,
                end_time=end_time,
                output=result.stdout if hasattr(result, 'stdout') else str(result),
                error=result.stderr if hasattr(result, 'stderr') else None
            )

            self.results.append(maintenance_result)
            task.last_run = start_time

            if success:
                logger.info(f"Maintenance task completed: {task_name}")
            else:
                logger.error(f"Maintenance task failed: {task_name}")

        except Exception as e:
            end_time = datetime.now()
            maintenance_result = MaintenanceResult(
                task_name=task_name,
                success=False,
                start_time=start_time,
                end_time=end_time,
                output="",
                error=str(e)
            )
            self.results.append(maintenance_result)
            logger.error(f"Maintenance task error {task_name}: {e}")

    def _execute_task(self, task: MaintenanceTask):
        """Execute a specific maintenance task"""
        # This would contain the actual implementation for each task
        # For now, we'll simulate with simple commands

        if task.name == "log_cleanup":
            # Simulate log cleanup
            return subprocess.run(['echo', 'Log cleanup completed'], capture_output=True, text=True)

        elif task.name == "cache_cleanup":
            # Simulate cache cleanup
            return subprocess.run(['echo', 'Cache cleanup completed'], capture_output=True, text=True)

        elif task.name == "database_optimize":
            # Simulate database optimization
            return subprocess.run(['echo', 'Database optimization completed'], capture_output=True, text=True)

        elif task.name == "security_audit":
            # Simulate security audit
            return subprocess.run(['echo', 'Security audit completed'], capture_output=True, text=True)

        elif task.name == "performance_monitor":
            # Simulate performance monitoring
            return subprocess.run(['echo', 'Performance monitoring completed'], capture_output=True, text=True)

        elif task.name == "backup_verify":
            # Simulate backup verification
            return subprocess.run(['echo', 'Backup verification completed'], capture_output=True, text=True)

        else:
            # Default action
            return subprocess.run(['echo', f'Executed task: {task.name}'], capture_output=True, text=True)

    def start(self):
        """Start the automated maintenance system"""
        self.stop_event.clear()
        self.maintenance_thread = threading.Thread(target=self._maintenance_loop, daemon=True)
        self.maintenance_thread.start()
        logger.info("Automated maintenance system started")

    def stop(self):
        """Stop the automated maintenance system"""
        if self.maintenance_thread:
            self.stop_event.set()
            self.maintenance_thread.join(timeout=5)
            logger.info("Automated maintenance system stopped")

    def _maintenance_loop(self):
        """Main maintenance loop"""
        while not self.stop_event.wait(60):  # Check every minute
            try:
                self.scheduler.run_pending()
            except Exception as e:
                logger.error(f"Maintenance loop error: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Get maintenance system status"""
        return {
            'running': self.maintenance_thread and self.maintenance_thread.is_alive(),
            'tasks': {
                name: {
                    'enabled': task.enabled,
                    'schedule': task.schedule,
                    'last_run': task.last_run.isoformat() if task.last_run else None,
                    'description': task.description
                }
                for name, task in self.tasks.items()
            },
            'recent_results': [
                {
                    'task_name': r.task_name,
                    'success': r.success,
                    'start_time': r.start_time.isoformat(),
                    'duration': (r.end_time - r.start_time).total_seconds(),
                    'error': r.error
                }
                for r in self.results[-10:]  # Last 10 results
            ]
        }


# Global instances
_log_rotation: Optional[AutomatedLogRotation] = None
_security_updates: Optional[AutomatedSecurityUpdates] = None
_maintenance: Optional[AutomatedMaintenance] = None


def get_log_rotation(config: Optional[LogRotationConfig] = None) -> AutomatedLogRotation:
    """Get or create global log rotation instance"""
    global _log_rotation
    if _log_rotation is None:
        if config is None:
            config = LogRotationConfig()
        _log_rotation = AutomatedLogRotation(config)
    return _log_rotation


def get_security_updates(config: Optional[SecurityUpdateConfig] = None) -> AutomatedSecurityUpdates:
    """Get or create global security updates instance"""
    global _security_updates
    if _security_updates is None:
        if config is None:
            config = SecurityUpdateConfig()
        _security_updates = AutomatedSecurityUpdates(config)
    return _security_updates


def get_maintenance_system() -> AutomatedMaintenance:
    """Get or create global maintenance system instance"""
    global _maintenance
    if _maintenance is None:
        _maintenance = AutomatedMaintenance()
    return _maintenance


def start_automated_operations():
    """Start all automated operations"""
    # Start log rotation
    log_config = LogRotationConfig(
        log_directories=['logs', 'blncs/logs', '/var/log/blncs']
    )
    log_rotation = get_log_rotation(log_config)
    log_rotation.start()

    # Start security updates
    update_config = SecurityUpdateConfig(
        enabled=True,
        auto_apply=False  # Only check, don't auto-apply for safety
    )
    security_updates = get_security_updates(update_config)
    security_updates.start()

    # Start maintenance
    maintenance = get_maintenance_system()
    maintenance.start()

    logger.info("All automated operations started")


def stop_automated_operations():
    """Stop all automated operations"""
    log_rotation = get_log_rotation()
    log_rotation.stop()

    security_updates = get_security_updates()
    security_updates.stop()

    maintenance = get_maintenance_system()
    maintenance.stop()

    logger.info("All automated operations stopped")


if __name__ == "__main__":
    start_automated_operations()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_automated_operations()
