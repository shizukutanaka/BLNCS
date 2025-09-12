"""
Automatic Maintenance and Cleanup Tasks for BLNCS
Practical maintenance routines to keep the system healthy.
"""

import os
import time
import threading
import logging
from pathlib import Path
from typing import Dict, List, Callable, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class MaintenanceTask:
    """Individual maintenance task configuration"""
    name: str
    description: str
    function: Callable
    interval_minutes: int
    enabled: bool = True
    last_run: Optional[datetime] = None
    run_count: int = 0
    error_count: int = 0

class MaintenanceManager:
    """Manages automatic cleanup and maintenance tasks"""
    
    def __init__(self, config_manager=None):
        self.config = config_manager
        self.tasks: Dict[str, MaintenanceTask] = {}
        self.running = False
        self.maintenance_thread = None
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
        
        # Register default maintenance tasks
        self._register_default_tasks()
    
    def _register_default_tasks(self):
        """Register default maintenance tasks"""
        # Cache cleanup
        self.register_task(
            'cache_cleanup',
            'Clean expired cache entries',
            self._cleanup_cache,
            interval_minutes=30
        )
        
        # Log rotation
        self.register_task(
            'log_rotation',
            'Rotate and compress old log files',
            self._rotate_logs,
            interval_minutes=60
        )
        
        # Database maintenance
        self.register_task(
            'database_vacuum',
            'Vacuum and optimize database',
            self._vacuum_database,
            interval_minutes=720  # 12 hours
        )
        
        # Temp file cleanup
        self.register_task(
            'temp_cleanup',
            'Remove temporary files',
            self._cleanup_temp_files,
            interval_minutes=60
        )
        
        # Error log monitoring
        self.register_task(
            'error_monitoring',
            'Monitor and report error patterns',
            self._monitor_errors,
            interval_minutes=15
        )
    
    def register_task(self, name: str, description: str, function: Callable, 
                     interval_minutes: int, enabled: bool = True):
        """Register a new maintenance task"""
        task = MaintenanceTask(
            name=name,
            description=description,
            function=function,
            interval_minutes=interval_minutes,
            enabled=enabled
        )
        
        with self.lock:
            self.tasks[name] = task
            self.logger.info(f"Registered maintenance task: {name}")
    
    def start(self):
        """Start maintenance scheduler"""
        if self.running:
            return
        
        self.running = True
        self.maintenance_thread = threading.Thread(target=self._maintenance_loop, daemon=True)
        self.maintenance_thread.start()
        self.logger.info("Maintenance scheduler started")
    
    def stop(self):
        """Stop maintenance scheduler"""
        self.running = False
        if self.maintenance_thread:
            self.maintenance_thread.join(timeout=5)
        self.logger.info("Maintenance scheduler stopped")
    
    def _maintenance_loop(self):
        """Main maintenance loop"""
        while self.running:
            current_time = datetime.now()
            
            with self.lock:
                tasks_to_run = []
                
                for name, task in self.tasks.items():
                    if not task.enabled:
                        continue
                    
                    # Check if task should run
                    if task.last_run is None:
                        tasks_to_run.append((name, task))
                    else:
                        time_since_last = current_time - task.last_run
                        if time_since_last.total_seconds() >= task.interval_minutes * 60:
                            tasks_to_run.append((name, task))
            
            # Run tasks outside of lock
            for name, task in tasks_to_run:
                try:
                    self.logger.debug(f"Running maintenance task: {name}")
                    start_time = time.time()
                    
                    task.function()
                    
                    execution_time = time.time() - start_time
                    
                    # Update task status
                    with self.lock:
                        task.last_run = current_time
                        task.run_count += 1
                    
                    self.logger.info(f"Maintenance task '{name}' completed in {execution_time:.2f}s")
                    
                except Exception as e:
                    with self.lock:
                        task.error_count += 1
                    self.logger.error(f"Maintenance task '{name}' failed: {e}")
            
            # Sleep for 60 seconds before next check
            time.sleep(60)
    
    def _cleanup_cache(self):
        """Clean expired cache entries"""
        try:
            from .cache_unified import get_cache
            cache = get_cache()
            
            # Cleanup expired entries
            removed = cache.cleanup_expired()
            if removed > 0:
                self.logger.info(f"Cache cleanup removed {removed} expired entries")
        except Exception as e:
            self.logger.warning(f"Cache cleanup failed: {e}")
    
    def _rotate_logs(self):
        """Rotate and compress old log files"""
        try:
            if self.config:
                data_dir = self.config.get_data_dir()
                logs_dir = data_dir / "logs"
            else:
                logs_dir = Path("logs")
            
            if not logs_dir.exists():
                return
            
            rotated_count = 0
            max_size_mb = 50
            
            for log_file in logs_dir.glob("*.log"):
                if log_file.stat().st_size > max_size_mb * 1024 * 1024:
                    # Rotate large log files
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    rotated_name = f"{log_file.stem}_{timestamp}.log"
                    rotated_path = logs_dir / rotated_name
                    
                    log_file.rename(rotated_path)
                    rotated_count += 1
            
            if rotated_count > 0:
                self.logger.info(f"Rotated {rotated_count} log files")
                
        except Exception as e:
            self.logger.warning(f"Log rotation failed: {e}")
    
    def _vacuum_database(self):
        """Vacuum and optimize database"""
        try:
            from .database import get_database
            db = get_database()
            
            # Vacuum database to optimize storage
            start_time = time.time()
            db.vacuum()
            vacuum_time = time.time() - start_time
            
            self.logger.info(f"Database vacuum completed in {vacuum_time:.2f}s")
            
        except Exception as e:
            self.logger.warning(f"Database vacuum failed: {e}")
    
    def _cleanup_temp_files(self):
        """Remove temporary files"""
        try:
            temp_patterns = ["*.tmp", "*.temp", "*~", ".#*", "core.*"]
            removed_count = 0
            max_age_hours = 24
            cutoff_time = time.time() - (max_age_hours * 3600)
            
            # Clean current directory
            for pattern in temp_patterns:
                for temp_file in Path(".").glob(pattern):
                    try:
                        if temp_file.is_file() and temp_file.stat().st_mtime < cutoff_time:
                            temp_file.unlink()
                            removed_count += 1
                    except OSError:
                        pass  # File might be in use
            
            # Clean system temp directory if accessible
            try:
                import tempfile
                temp_dir = Path(tempfile.gettempdir())
                for pattern in ["blncs_*", "lightning_*"]:
                    for temp_file in temp_dir.glob(pattern):
                        try:
                            if temp_file.is_file() and temp_file.stat().st_mtime < cutoff_time:
                                temp_file.unlink()
                                removed_count += 1
                        except OSError:
                            pass
            except:
                pass
            
            if removed_count > 0:
                self.logger.info(f"Cleaned up {removed_count} temporary files")
                
        except Exception as e:
            self.logger.warning(f"Temp file cleanup failed: {e}")
    
    def _monitor_errors(self):
        """Monitor and report error patterns"""
        try:
            # Simple error monitoring - check recent logs for error patterns
            error_patterns = ["ERROR", "CRITICAL", "Exception", "Failed"]
            error_count = 0
            
            # Check if there's a way to access recent log entries
            # This is a simplified implementation
            recent_errors = []
            
            # Could implement more sophisticated error monitoring here
            # For now, just check if error recovery manager has recent errors
            try:
                from .error_recovery import get_error_recovery_manager
                recovery_manager = get_error_recovery_manager()
                error_summary = recovery_manager.get_error_summary()
                
                recent_error_count = len(error_summary.get('recent_errors', []))
                if recent_error_count > 5:  # More than 5 errors recently
                    self.logger.warning(f"High error rate detected: {recent_error_count} recent errors")
                    
            except Exception:
                pass  # Error recovery not available
                
        except Exception as e:
            self.logger.warning(f"Error monitoring failed: {e}")
    
    def run_task_now(self, name: str) -> bool:
        """Run a specific maintenance task immediately"""
        with self.lock:
            task = self.tasks.get(name)
            if not task:
                return False
        
        try:
            self.logger.info(f"Manually running maintenance task: {name}")
            start_time = time.time()
            
            task.function()
            
            execution_time = time.time() - start_time
            
            with self.lock:
                task.last_run = datetime.now()
                task.run_count += 1
            
            self.logger.info(f"Task '{name}' completed in {execution_time:.2f}s")
            return True
            
        except Exception as e:
            with self.lock:
                task.error_count += 1
            self.logger.error(f"Task '{name}' failed: {e}")
            return False
    
    def get_task_status(self) -> Dict[str, Dict]:
        """Get status of all maintenance tasks"""
        with self.lock:
            status = {}
            for name, task in self.tasks.items():
                status[name] = {
                    'description': task.description,
                    'enabled': task.enabled,
                    'interval_minutes': task.interval_minutes,
                    'last_run': task.last_run.isoformat() if task.last_run else None,
                    'run_count': task.run_count,
                    'error_count': task.error_count,
                    'next_run': None
                }
                
                if task.last_run and task.enabled:
                    next_run = task.last_run + timedelta(minutes=task.interval_minutes)
                    status[name]['next_run'] = next_run.isoformat()
            
            return status
    
    def enable_task(self, name: str) -> bool:
        """Enable a maintenance task"""
        with self.lock:
            if name in self.tasks:
                self.tasks[name].enabled = True
                return True
            return False
    
    def disable_task(self, name: str) -> bool:
        """Disable a maintenance task"""
        with self.lock:
            if name in self.tasks:
                self.tasks[name].enabled = False
                return True
            return False

# Create singleton instance
_maintenance_manager_instance = None
_maintenance_lock = threading.Lock()

def get_maintenance_manager(config_manager=None) -> MaintenanceManager:
    """Get or create maintenance manager instance"""
    global _maintenance_manager_instance
    if _maintenance_manager_instance is None:
        with _maintenance_lock:
            if _maintenance_manager_instance is None:
                _maintenance_manager_instance = MaintenanceManager(config_manager)
    return _maintenance_manager_instance

def start_maintenance():
    """Start automatic maintenance tasks"""
    manager = get_maintenance_manager()
    manager.start()

def stop_maintenance():
    """Stop automatic maintenance tasks"""
    manager = get_maintenance_manager()
    manager.stop()

__all__ = [
    'MaintenanceManager', 'MaintenanceTask', 'get_maintenance_manager',
    'start_maintenance', 'stop_maintenance'
]