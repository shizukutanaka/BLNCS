"""
BLNCS Maintenance Scheduler
Automated System Maintenance for Enterprise Stability

This module provides comprehensive maintenance automation:
- Scheduled maintenance tasks with intelligent timing
- System health optimization routines
- Preventive maintenance to avoid issues
- Performance tuning and optimization
- Database maintenance and cleanup
- Log rotation and system cleanup
- Automated security updates and patches
"""

import os
import sys
import time
import json
import logging
import threading
import subprocess
# import schedule  # Optional dependency
import shutil
import gzip
from typing import Dict, List, Any, Optional, Callable, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import sqlite3
import glob
import tempfile


DEFAULT_LOG_DIR = os.environ.get("BLNCS_MAINTENANCE_LOG_DIR", "/var/log/blncs/maintenance")
DEFAULT_DB_PATH = os.environ.get("BLNCS_MAINTENANCE_DB", "/var/lib/blncs/maintenance.db")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

class MaintenanceType(Enum):
    """Types of maintenance tasks"""
    SYSTEM_CLEANUP = "system_cleanup"
    DATABASE_OPTIMIZATION = "database_optimization"
    LOG_ROTATION = "log_rotation"
    SECURITY_UPDATE = "security_update"
    PERFORMANCE_TUNING = "performance_tuning"
    BACKUP_VERIFICATION = "backup_verification"
    HEALTH_CHECK = "health_check"
    CACHE_CLEANUP = "cache_cleanup"

class MaintenancePriority(Enum):
    """Maintenance task priority levels"""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4

class TaskStatus(Enum):
    """Maintenance task status"""
    SCHEDULED = "scheduled"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"

@dataclass
class MaintenanceTask:
    """Maintenance task definition"""
    task_id: str
    name: str
    description: str
    task_type: MaintenanceType
    priority: MaintenancePriority
    schedule_expression: str  # Cron-like expression
    estimated_duration: int  # minutes
    max_runtime: int  # minutes
    requires_downtime: bool = False
    dependencies: List[str] = field(default_factory=list)
    handler_function: Optional[Callable] = None
    last_run: Optional[datetime] = None
    last_status: TaskStatus = TaskStatus.SCHEDULED
    last_error: str = ""

@dataclass
class MaintenanceWindow:
    """Maintenance window configuration"""
    window_id: str
    name: str
    start_time: str  # HH:MM format
    end_time: str  # HH:MM format
    days_of_week: List[int]  # 0=Monday, 6=Sunday
    timezone: str = "UTC"
    allow_critical_only: bool = False

@dataclass
class MaintenanceReport:
    """Maintenance execution report"""
    report_id: str
    start_time: datetime
    end_time: datetime
    tasks_executed: int
    tasks_successful: int
    tasks_failed: int
    total_duration: int  # minutes
    system_impact: str
    issues_found: List[str]
    recommendations: List[str]

class MaintenanceScheduler:
    """
    Automated System Maintenance Scheduler

    Provides comprehensive maintenance automation:
    - Intelligent task scheduling with maintenance windows
    - System health optimization and preventive maintenance
    - Performance tuning and resource optimization
    - Database maintenance and log management
    - Automated security updates and compliance checks
    """

    def __init__(self, config_path: Optional[str] = None):
        self.logger = self._setup_maintenance_logging()
        self.tasks: Dict[str, MaintenanceTask] = {}
        self.maintenance_windows: Dict[str, MaintenanceWindow] = {}
        self.execution_history: List[MaintenanceReport] = []

        # Scheduler state
        self.scheduler_active = False
        self.scheduler_thread: Optional[threading.Thread] = None
        self.current_tasks: Dict[str, threading.Thread] = {}
        self.task_lock = threading.Lock()

        # System monitoring
        self.system_metrics = {}
        self.maintenance_impact = {}

        # Database for maintenance data
        self.db_path = DEFAULT_DB_PATH
        self._initialize_database()

        # Load configuration
        self._load_configuration(config_path)
        self._register_default_tasks()
        self._register_default_windows()

        self.logger.info("Maintenance Scheduler initialized")

    def _setup_maintenance_logging(self) -> logging.Logger:
        """Setup maintenance-specific logging"""
        logger = logging.getLogger("BLNCS_Maintenance")
        logger.setLevel(logging.INFO)

        # Maintenance log directory
        log_dir = DEFAULT_LOG_DIR
        os.makedirs(log_dir, mode=0o755, exist_ok=True)

        # File handler
        handler = logging.FileHandler(f"{log_dir}/maintenance.log", mode='a')
        handler.setLevel(logging.INFO)

        formatter = logging.Formatter(
            '%(asctime)s|%(levelname)s|%(name)s|%(message)s',
            datefmt='%Y-%m-%d %H:%M:%S UTC'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        return logger

    def _initialize_database(self):
        """Initialize maintenance database"""
        try:
            os.makedirs(os.path.dirname(self.db_path), mode=0o755, exist_ok=True)
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS maintenance_tasks (
                    task_id TEXT PRIMARY KEY,
                    name TEXT,
                    description TEXT,
                    task_type TEXT,
                    priority INTEGER,
                    schedule_expression TEXT,
                    estimated_duration INTEGER,
                    max_runtime INTEGER,
                    requires_downtime INTEGER,
                    dependencies TEXT,
                    last_run TEXT,
                    last_status TEXT,
                    last_error TEXT
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS maintenance_reports (
                    report_id TEXT PRIMARY KEY,
                    start_time TEXT,
                    end_time TEXT,
                    tasks_executed INTEGER,
                    tasks_successful INTEGER,
                    tasks_failed INTEGER,
                    total_duration INTEGER,
                    system_impact TEXT,
                    issues_found TEXT,
                    recommendations TEXT
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS maintenance_windows (
                    window_id TEXT PRIMARY KEY,
                    name TEXT,
                    start_time TEXT,
                    end_time TEXT,
                    days_of_week TEXT,
                    timezone TEXT,
                    allow_critical_only INTEGER
                )
            ''')

            conn.commit()
            conn.close()

            self.logger.info("Maintenance database initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize maintenance database: {e}")

    def _load_configuration(self, config_path: Optional[str]):
        """Load maintenance configuration"""
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)

                # Load maintenance windows
                for window_data in config.get('maintenance_windows', []):
                    window = MaintenanceWindow(
                        window_id=window_data['window_id'],
                        name=window_data['name'],
                        start_time=window_data['start_time'],
                        end_time=window_data['end_time'],
                        days_of_week=window_data['days_of_week'],
                        timezone=window_data.get('timezone', 'UTC'),
                        allow_critical_only=window_data.get('allow_critical_only', False)
                    )
                    self.maintenance_windows[window.window_id] = window

                self.logger.info(f"Loaded {len(self.maintenance_windows)} maintenance windows")

            except Exception as e:
                self.logger.error(f"Failed to load maintenance configuration: {e}")

    def _register_default_tasks(self):
        """Register default maintenance tasks"""
        default_tasks = [
            MaintenanceTask(
                task_id="daily_system_cleanup",
                name="Daily System Cleanup",
                description="Clean up temporary files and system caches",
                task_type=MaintenanceType.SYSTEM_CLEANUP,
                priority=MaintenancePriority.NORMAL,
                schedule_expression="0 2 * * *",  # 2 AM daily
                estimated_duration=15,
                max_runtime=30,
                handler_function=self._system_cleanup_handler
            ),
            MaintenanceTask(
                task_id="weekly_database_optimization",
                name="Weekly Database Optimization",
                description="Optimize database performance and clean up old data",
                task_type=MaintenanceType.DATABASE_OPTIMIZATION,
                priority=MaintenancePriority.HIGH,
                schedule_expression="0 3 * * 0",  # 3 AM every Sunday
                estimated_duration=45,
                max_runtime=120,
                handler_function=self._database_optimization_handler
            ),
            MaintenanceTask(
                task_id="daily_log_rotation",
                name="Daily Log Rotation",
                description="Rotate and compress system logs",
                task_type=MaintenanceType.LOG_ROTATION,
                priority=MaintenancePriority.NORMAL,
                schedule_expression="0 1 * * *",  # 1 AM daily
                estimated_duration=10,
                max_runtime=20,
                handler_function=self._log_rotation_handler
            ),
            MaintenanceTask(
                task_id="weekly_security_update",
                name="Weekly Security Update Check",
                description="Check and apply security updates",
                task_type=MaintenanceType.SECURITY_UPDATE,
                priority=MaintenancePriority.CRITICAL,
                schedule_expression="0 4 * * 0",  # 4 AM every Sunday
                estimated_duration=30,
                max_runtime=60,
                handler_function=self._security_update_handler
            ),
            MaintenanceTask(
                task_id="hourly_health_check",
                name="Hourly Health Check",
                description="Check system health and performance metrics",
                task_type=MaintenanceType.HEALTH_CHECK,
                priority=MaintenancePriority.HIGH,
                schedule_expression="0 * * * *",  # Every hour
                estimated_duration=5,
                max_runtime=10,
                handler_function=self._health_check_handler
            ),
            MaintenanceTask(
                task_id="daily_performance_tuning",
                name="Daily Performance Tuning",
                description="Optimize system performance based on usage patterns",
                task_type=MaintenanceType.PERFORMANCE_TUNING,
                priority=MaintenancePriority.NORMAL,
                schedule_expression="0 5 * * *",  # 5 AM daily
                estimated_duration=20,
                max_runtime=40,
                handler_function=self._performance_tuning_handler
            )
        ]

        for task in default_tasks:
            self.tasks[task.task_id] = task
            self._save_task_to_database(task)

    def _register_default_windows(self):
        """Register default maintenance windows"""
        default_windows = [
            MaintenanceWindow(
                window_id="daily_maintenance",
                name="Daily Maintenance Window",
                start_time="02:00",
                end_time="06:00",
                days_of_week=[0, 1, 2, 3, 4, 5, 6],  # Every day
                timezone="UTC"
            ),
            MaintenanceWindow(
                window_id="weekend_maintenance",
                name="Weekend Maintenance Window",
                start_time="01:00",
                end_time="07:00",
                days_of_week=[5, 6],  # Saturday and Sunday
                timezone="UTC",
                allow_critical_only=False
            )
        ]

        for window in default_windows:
            if window.window_id not in self.maintenance_windows:
                self.maintenance_windows[window.window_id] = window
                self._save_window_to_database(window)

    def start_scheduler(self):
        """Start the maintenance scheduler"""
        if self.scheduler_active:
            return

        self.scheduler_active = True
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.scheduler_thread.start()

        self.logger.info("Maintenance scheduler started")

    def _scheduler_loop(self):
        """Main maintenance scheduler loop"""
        while self.scheduler_active:
            try:
                current_time = datetime.utcnow()

                # Check for scheduled maintenance tasks
                for task in self.tasks.values():
                    if self._should_run_task(task, current_time):
                        if self._can_run_in_maintenance_window(task, current_time):
                            self._schedule_task_execution(task)

                # Clean up completed task threads
                self._cleanup_completed_tasks()

                # Monitor system impact
                self._monitor_system_impact()

                # Sleep for 60 seconds
                time.sleep(60)

            except Exception as e:
                self.logger.error(f"Scheduler error: {e}")
                time.sleep(300)  # 5-minute error recovery delay

    def _should_run_task(self, task: MaintenanceTask, current_time: datetime) -> bool:
        """Check if task should run based on schedule"""
        # Simple cron-like scheduling check
        cron_parts = task.schedule_expression.split()
        if len(cron_parts) != 5:
            return False

        minute, hour, day, month, weekday = cron_parts

        # Check minute
        if minute != "*" and int(minute) != current_time.minute:
            return False

        # Check hour
        if hour != "*" and int(hour) != current_time.hour:
            return False

        # Check if task already running
        if task.task_id in self.current_tasks:
            return False

        # Check if task ran recently
        if task.last_run:
            time_since_last = current_time - task.last_run
            if time_since_last < timedelta(hours=1):
                return False

        return True

    def _can_run_in_maintenance_window(self, task: MaintenanceTask, current_time: datetime) -> bool:
        """Check if task can run in current maintenance window"""
        current_time_str = current_time.strftime("%H:%M")
        current_weekday = current_time.weekday()

        for window in self.maintenance_windows.values():
            # Check if current day is in window days
            if current_weekday not in window.days_of_week:
                continue

            # Check if current time is in window
            if window.start_time <= current_time_str <= window.end_time:
                # Check if task priority is allowed
                if window.allow_critical_only and task.priority != MaintenancePriority.CRITICAL:
                    continue

                return True

        # Critical tasks can run outside maintenance windows
        return task.priority == MaintenancePriority.CRITICAL

    def _schedule_task_execution(self, task: MaintenanceTask):
        """Schedule task for execution"""
        with self.task_lock:
            if task.task_id in self.current_tasks:
                return  # Task already running

            # Create and start task thread
            task_thread = threading.Thread(
                target=self._execute_task,
                args=(task,),
                daemon=True
            )

            self.current_tasks[task.task_id] = task_thread
            task_thread.start()

            self.logger.info(f"Scheduled task execution: {task.name}")

    def _execute_task(self, task: MaintenanceTask):
        """Execute a maintenance task in a worker thread"""
        result = self._run_task_internal(task, invoked_by="scheduler")

        # Remove from current tasks once complete
        with self.task_lock:
            if task.task_id in self.current_tasks:
                del self.current_tasks[task.task_id]

        if result['status'] == TaskStatus.COMPLETED.value:
            self.logger.info(f"Maintenance task completed: {task.name} ({result['status']})")
        elif result['status'] == TaskStatus.SKIPPED.value:
            self.logger.warning(f"Maintenance task skipped: {task.name} ({result['reason']})")
        else:
            self.logger.error(f"Maintenance task failed: {task.name}: {task.last_error}")

    def _run_task_internal(
        self,
        task: MaintenanceTask,
        *,
        invoked_by: str = "manual",
        respect_windows: bool = False
    ) -> Dict[str, Any]:
        """Execute a maintenance task synchronously and return structured result."""

        now = datetime.utcnow()
        if respect_windows and not self._can_run_in_maintenance_window(task, now):
            return {
                'task_id': task.task_id,
                'name': task.name,
                'status': TaskStatus.SKIPPED.value,
                'reason': 'outside_maintenance_window'
            }

        self.logger.info(f"Starting maintenance task: {task.name} (invoked_by={invoked_by})")

        task.last_run = now
        task.last_status = TaskStatus.RUNNING
        task.last_error = ""

        start_time = time.time()
        timeout = task.max_runtime * 60  # seconds
        handler_result: Dict[str, Any] = {}

        try:
            if not task.handler_function:
                task.last_status = TaskStatus.FAILED
                task.last_error = "No handler function defined"
                handler_result = {'success': False, 'error': task.last_error}
            else:
                handler_result = task.handler_function(task) or {}
                execution_time = time.time() - start_time

                if execution_time > timeout:
                    task.last_status = TaskStatus.FAILED
                    task.last_error = f"Task exceeded maximum runtime ({task.max_runtime} minutes)"
                elif handler_result.get('success', False):
                    task.last_status = TaskStatus.COMPLETED
                    task.last_error = ""
                else:
                    task.last_status = TaskStatus.FAILED
                    task.last_error = handler_result.get('error', 'Unknown error')

        except Exception as exc:  # pylint: disable=broad-except
            task.last_status = TaskStatus.FAILED
            task.last_error = str(exc)
            handler_result = {'success': False, 'error': task.last_error}
            self.logger.exception("Maintenance task raised an exception: %s", task.name)

        finally:
            self._save_task_to_database(task)

        duration = time.time() - start_time

        return {
            'task_id': task.task_id,
            'name': task.name,
            'status': task.last_status.value,
            'duration_seconds': round(duration, 3),
            'details': handler_result,
            'invoked_by': invoked_by,
            'last_error': task.last_error
        }

    def list_tasks_summary(
        self,
        minimum_priority: Optional[MaintenancePriority] = None
    ) -> List[Dict[str, Any]]:
        """Return summaries for registered maintenance tasks."""

        summaries: List[Dict[str, Any]] = []
        for task in self.tasks.values():
            if minimum_priority and task.priority.value < minimum_priority.value:
                continue
            summaries.append({
                'task_id': task.task_id,
                'name': task.name,
                'type': task.task_type.value,
                'priority': task.priority.name,
                'priority_value': task.priority.value,
                'schedule': task.schedule_expression,
                'requires_downtime': task.requires_downtime,
                'last_run': task.last_run.isoformat() if task.last_run else None,
                'last_status': task.last_status.value,
                'estimated_duration_minutes': task.estimated_duration
            })
        return sorted(summaries, key=lambda item: item['priority_value'], reverse=True)

    def run_tasks_now(
        self,
        task_ids: Optional[List[str]] = None,
        *,
        respect_windows: bool = False
    ) -> List[Dict[str, Any]]:
        """Execute one or more maintenance tasks synchronously."""

        if task_ids:
            selected = [self.tasks.get(task_id) for task_id in task_ids]
        else:
            selected = list(self.tasks.values())

        results: List[Dict[str, Any]] = []
        for task in selected:
            if task is None:
                results.append({'status': TaskStatus.SKIPPED.value, 'reason': 'unknown_task'})
                continue
            with self.task_lock:
                results.append(self._run_task_internal(task, invoked_by="manual", respect_windows=respect_windows))

        return results

    def run_priority_bundle(
        self,
        minimum_priority: MaintenancePriority = MaintenancePriority.HIGH,
        *,
        respect_windows: bool = False
    ) -> List[Dict[str, Any]]:
        """Execute all tasks meeting the minimum priority threshold."""

        task_ids = [task.task_id for task in self.tasks.values() if task.priority.value >= minimum_priority.value]
        return self.run_tasks_now(task_ids, respect_windows=respect_windows)

    def _system_cleanup_handler(self, task: MaintenanceTask) -> Dict[str, Any]:
        """Handle system cleanup maintenance"""
        try:
            cleaned_files = 0
            freed_space = 0

            # Clean temporary files
            temp_dirs = ["/tmp", "/var/tmp", "/opt/blncs/temp"]
            for temp_dir in temp_dirs:
                if os.path.exists(temp_dir):
                    for root, dirs, files in os.walk(temp_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            try:
                                # Delete files older than 7 days
                                if os.path.getmtime(file_path) < time.time() - (7 * 24 * 3600):
                                    size = os.path.getsize(file_path)
                                    os.remove(file_path)
                                    cleaned_files += 1
                                    freed_space += size
                            except OSError:
                                continue

            # Clean cache directories
            cache_dirs = ["/var/cache/blncs", "/opt/blncs/cache"]
            for cache_dir in cache_dirs:
                if os.path.exists(cache_dir):
                    try:
                        shutil.rmtree(cache_dir)
                        os.makedirs(cache_dir, mode=0o755)
                    except OSError:
                        pass

            return {
                'success': True,
                'cleaned_files': cleaned_files,
                'freed_space_mb': freed_space / (1024 * 1024),
                'details': f'Cleaned {cleaned_files} files, freed {freed_space / (1024 * 1024):.1f} MB'
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _database_optimization_handler(self, task: MaintenanceTask) -> Dict[str, Any]:
        """Handle database optimization maintenance"""
        try:
            optimized_tables = 0

            # Find all SQLite databases
            db_files = glob.glob("/var/lib/blncs/*.db") + glob.glob("/opt/blncs/data/*.db")

            for db_file in db_files:
                try:
                    conn = sqlite3.connect(db_file)
                    cursor = conn.cursor()

                    # Run VACUUM to optimize database
                    cursor.execute("VACUUM")

                    # Update statistics
                    cursor.execute("ANALYZE")

                    conn.close()
                    optimized_tables += 1

                except Exception as e:
                    self.logger.warning(f"Failed to optimize database {db_file}: {e}")

            return {
                'success': True,
                'optimized_databases': optimized_tables,
                'details': f'Optimized {optimized_tables} database files'
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _log_rotation_handler(self, task: MaintenanceTask) -> Dict[str, Any]:
        """Handle log rotation maintenance"""
        try:
            rotated_logs = 0
            compressed_logs = 0

            log_dirs = ["/var/log/blncs", "/opt/blncs/logs"]

            for log_dir in log_dirs:
                if not os.path.exists(log_dir):
                    continue

                # Find log files older than 1 day
                for log_file in glob.glob(os.path.join(log_dir, "*.log")):
                    if os.path.getmtime(log_file) < time.time() - (24 * 3600):
                        # Compress the log file
                        compressed_name = f"{log_file}.{datetime.now().strftime('%Y%m%d')}.gz"

                        with open(log_file, 'rb') as f_in:
                            with gzip.open(compressed_name, 'wb') as f_out:
                                shutil.copyfileobj(f_in, f_out)

                        # Truncate original log file
                        with open(log_file, 'w') as f:
                            pass

                        rotated_logs += 1
                        compressed_logs += 1

                # Clean up old compressed logs (older than 30 days)
                for compressed_log in glob.glob(os.path.join(log_dir, "*.gz")):
                    if os.path.getmtime(compressed_log) < time.time() - (30 * 24 * 3600):
                        os.remove(compressed_log)

            return {
                'success': True,
                'rotated_logs': rotated_logs,
                'compressed_logs': compressed_logs,
                'details': f'Rotated {rotated_logs} logs, compressed {compressed_logs} files'
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _health_check_handler(self, task: MaintenanceTask) -> Dict[str, Any]:
        """Handle system health check maintenance"""
        try:
            health_issues = []
            health_score = 100

            # Check disk space
            if PSUTIL_AVAILABLE:
                disk_usage = psutil.disk_usage('/')
                disk_percent = (disk_usage.used / disk_usage.total) * 100

                if disk_percent > 90:
                    health_issues.append(f"Disk usage critical: {disk_percent:.1f}%")
                    health_score -= 20
                elif disk_percent > 80:
                    health_issues.append(f"Disk usage high: {disk_percent:.1f}%")
                    health_score -= 10

                # Check memory usage
                memory = psutil.virtual_memory()
                if memory.percent > 90:
                    health_issues.append(f"Memory usage critical: {memory.percent:.1f}%")
                    health_score -= 15
                elif memory.percent > 80:
                    health_issues.append(f"Memory usage high: {memory.percent:.1f}%")
                    health_score -= 5

                # Check CPU usage
                cpu_percent = psutil.cpu_percent(interval=1)
                if cpu_percent > 90:
                    health_issues.append(f"CPU usage critical: {cpu_percent:.1f}%")
                    health_score -= 15

            # Check critical services
            critical_files = [
                "/opt/blncs/blncs_main.py",
                "/opt/blncs/config/blncs.json"
            ]

            for file_path in critical_files:
                if not os.path.exists(file_path):
                    health_issues.append(f"Critical file missing: {file_path}")
                    health_score -= 25

            return {
                'success': True,
                'health_score': health_score,
                'issues_found': len(health_issues),
                'health_issues': health_issues,
                'details': f'Health score: {health_score}/100, {len(health_issues)} issues found'
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_maintenance_status(self) -> Dict[str, Any]:
        """Get comprehensive maintenance status"""
        total_tasks = len(self.tasks)
        running_tasks = len(self.current_tasks)
        completed_tasks = len([t for t in self.tasks.values() if t.last_status == TaskStatus.COMPLETED])
        failed_tasks = len([t for t in self.tasks.values() if t.last_status == TaskStatus.FAILED])

        return {
            'scheduler_active': self.scheduler_active,
            'total_tasks': total_tasks,
            'running_tasks': running_tasks,
            'completed_tasks': completed_tasks,
            'failed_tasks': failed_tasks,
            'success_rate': (completed_tasks / max(total_tasks, 1)) * 100,
            'maintenance_windows': len(self.maintenance_windows),
            'last_maintenance_report': self._get_last_report_summary(),
            'next_scheduled_tasks': self._get_next_scheduled_tasks(),
            'system_impact': self._calculate_system_impact()
        }

    def get_maintenance_report(self, days: int = 7) -> Dict[str, Any]:
        """Generate maintenance report for specified period"""
        cutoff_date = datetime.utcnow() - timedelta(days=days)

        recent_tasks = [
            task for task in self.tasks.values()
            if task.last_run and task.last_run > cutoff_date
        ]

        return {
            'report_period_days': days,
            'total_tasks_executed': len(recent_tasks),
            'successful_tasks': len([t for t in recent_tasks if t.last_status == TaskStatus.COMPLETED]),
            'failed_tasks': len([t for t in recent_tasks if t.last_status == TaskStatus.FAILED]),
            'maintenance_by_type': self._group_tasks_by_type(recent_tasks),
            'average_execution_time': self._calculate_average_execution_time(recent_tasks),
            'system_improvements': self._calculate_system_improvements(),
            'recommendations': self._generate_maintenance_recommendations()
        }

    def shutdown(self):
        """Shutdown the maintenance scheduler"""
        self.logger.info("Shutting down maintenance scheduler")

        self.scheduler_active = False

        # Wait for scheduler thread
        if self.scheduler_thread and self.scheduler_thread.is_alive():
            self.scheduler_thread.join(timeout=10)

        # Wait for running tasks to complete
        timeout = 300  # 5 minutes
        start_time = time.time()
        while self.current_tasks and (time.time() - start_time) < timeout:
            time.sleep(5)

        self.logger.info("Maintenance scheduler shutdown completed")

def initialize_maintenance_scheduler(config_path: Optional[str] = None) -> MaintenanceScheduler:
    """Initialize maintenance scheduler"""
    return MaintenanceScheduler(config_path)

if __name__ == "__main__":
    # Test maintenance scheduler
    scheduler = initialize_maintenance_scheduler()
    scheduler.start_scheduler()

    print("Maintenance Scheduler Status:")
    status = scheduler.get_maintenance_status()
    for key, value in status.items():
        print(f"  {key}: {value}")

    print(f"\nMaintenance Report (last 7 days):")
    report = scheduler.get_maintenance_report(days=7)
    for key, value in report.items():
        print(f"  {key}: {value}")

    # Keep running for a short time
    time.sleep(60)

    scheduler.shutdown()