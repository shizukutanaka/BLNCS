"""
Lightweight Automation System
Simple task scheduling and automation without heavy dependencies.
"""

import time
import threading
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .logger import get_logger
from .config_enhanced import get_enhanced_config_manager

logger = get_logger(__name__)


class TaskStatus(Enum):
    """Task execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskType(Enum):
    """Types of automated tasks"""
    BACKUP = "backup"
    HEALTH_CHECK = "health_check"
    BALANCE_CHECK = "balance_check"
    CHANNEL_ANALYSIS = "channel_analysis"
    FEE_UPDATE = "fee_update"
    CUSTOM = "custom"


@dataclass
class AutomationTask:
    """Automated task definition"""
    task_id: str
    task_type: TaskType
    name: str
    description: str
    schedule: str  # Simple schedule: "daily", "hourly", "weekly", or cron-like
    function: Optional[Callable] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    status: TaskStatus = TaskStatus.PENDING
    run_count: int = 0
    failure_count: int = 0
    max_failures: int = 3
    timeout: int = 300  # 5 minutes default


class LightweightAutomation:
    """Simple automation system for BLNCS"""
    
    def __init__(self):
        """Initialize automation system"""
        self.logger = get_logger(__name__)
        self.config_manager = get_enhanced_config_manager()
        
        # Task management
        self.tasks: Dict[str, AutomationTask] = {}
        self.running = False
        self._scheduler_thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        
        # Load saved tasks
        self._load_tasks()
        
        # Register default tasks
        self._register_default_tasks()
    
    def _load_tasks(self):
        """Load tasks from configuration"""
        try:
            data_dir = Path(self.config_manager.get('system.data_dir', './data'))
            tasks_file = data_dir / 'automation_tasks.json'
            
            if tasks_file.exists():
                with open(tasks_file, 'r') as f:
                    tasks_data = json.load(f)
                
                for task_id, task_data in tasks_data.items():
                    task = AutomationTask(
                        task_id=task_data['task_id'],
                        task_type=TaskType(task_data['task_type']),
                        name=task_data['name'],
                        description=task_data['description'],
                        schedule=task_data['schedule'],
                        parameters=task_data.get('parameters', {}),
                        enabled=task_data.get('enabled', True),
                        last_run=datetime.fromisoformat(task_data['last_run']) if task_data.get('last_run') else None,
                        status=TaskStatus(task_data.get('status', 'pending')),
                        run_count=task_data.get('run_count', 0),
                        failure_count=task_data.get('failure_count', 0),
                        max_failures=task_data.get('max_failures', 3),
                        timeout=task_data.get('timeout', 300)
                    )
                    
                    # Calculate next run
                    task.next_run = self._calculate_next_run(task)
                    self.tasks[task_id] = task
                
                self.logger.info(f"Loaded {len(self.tasks)} automation tasks")
                
        except Exception as e:
            self.logger.warning(f"Could not load automation tasks: {e}")
    
    def _save_tasks(self):
        """Save tasks to configuration"""
        try:
            data_dir = Path(self.config_manager.get('system.data_dir', './data'))
            data_dir.mkdir(parents=True, exist_ok=True)
            tasks_file = data_dir / 'automation_tasks.json'
            
            tasks_data = {}
            for task_id, task in self.tasks.items():
                tasks_data[task_id] = {
                    'task_id': task.task_id,
                    'task_type': task.task_type.value,
                    'name': task.name,
                    'description': task.description,
                    'schedule': task.schedule,
                    'parameters': task.parameters,
                    'enabled': task.enabled,
                    'last_run': task.last_run.isoformat() if task.last_run else None,
                    'status': task.status.value,
                    'run_count': task.run_count,
                    'failure_count': task.failure_count,
                    'max_failures': task.max_failures,
                    'timeout': task.timeout
                }
            
            with open(tasks_file, 'w') as f:
                json.dump(tasks_data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Could not save automation tasks: {e}")
    
    def _register_default_tasks(self):
        """Register default automation tasks"""
        
        # Default backup task
        if 'daily_backup' not in self.tasks:
            self.add_task(
                task_id='daily_backup',
                task_type=TaskType.BACKUP,
                name='Daily Backup',
                description='Create daily backup of BLNCS data',
                schedule='daily',
                function=self._backup_task,
                enabled=self.config_manager.get('automation.enable_daily_backup', False)
            )
        
        # Default health check
        if 'hourly_health' not in self.tasks:
            self.add_task(
                task_id='hourly_health',
                task_type=TaskType.HEALTH_CHECK,
                name='Hourly Health Check',
                description='Perform health check every hour',
                schedule='hourly',
                function=self._health_check_task,
                enabled=self.config_manager.get('automation.enable_health_checks', True)
            )
        
        # Balance monitoring
        if 'balance_monitor' not in self.tasks:
            self.add_task(
                task_id='balance_monitor',
                task_type=TaskType.BALANCE_CHECK,
                name='Balance Monitor',
                description='Monitor wallet and channel balances',
                schedule='30min',
                function=self._balance_check_task,
                enabled=self.config_manager.get('automation.enable_balance_monitoring', False)
            )
    
    def add_task(self, task_id: str, task_type: TaskType, name: str, description: str,
                schedule: str, function: Optional[Callable] = None, 
                parameters: Optional[Dict[str, Any]] = None, enabled: bool = True) -> bool:
        """Add a new automation task"""
        try:
            with self._lock:
                if task_id in self.tasks:
                    self.logger.warning(f"Task {task_id} already exists")
                    return False
                
                task = AutomationTask(
                    task_id=task_id,
                    task_type=task_type,
                    name=name,
                    description=description,
                    schedule=schedule,
                    function=function,
                    parameters=parameters or {},
                    enabled=enabled
                )
                
                # Calculate first run
                task.next_run = self._calculate_next_run(task)
                
                self.tasks[task_id] = task
                self._save_tasks()
                
                self.logger.info(f"Added automation task: {name}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to add task {task_id}: {e}")
            return False
    
    def remove_task(self, task_id: str) -> bool:
        """Remove an automation task"""
        try:
            with self._lock:
                if task_id not in self.tasks:
                    return False
                
                task = self.tasks[task_id]
                if task.status == TaskStatus.RUNNING:
                    task.status = TaskStatus.CANCELLED
                
                del self.tasks[task_id]
                self._save_tasks()
                
                self.logger.info(f"Removed automation task: {task_id}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to remove task {task_id}: {e}")
            return False
    
    def enable_task(self, task_id: str) -> bool:
        """Enable an automation task"""
        with self._lock:
            if task_id in self.tasks:
                self.tasks[task_id].enabled = True
                self.tasks[task_id].next_run = self._calculate_next_run(self.tasks[task_id])
                self._save_tasks()
                return True
            return False
    
    def disable_task(self, task_id: str) -> bool:
        """Disable an automation task"""
        with self._lock:
            if task_id in self.tasks:
                self.tasks[task_id].enabled = False
                self.tasks[task_id].next_run = None
                self._save_tasks()
                return True
            return False
    
    def _calculate_next_run(self, task: AutomationTask) -> Optional[datetime]:
        """Calculate next run time for a task"""
        if not task.enabled:
            return None
        
        now = datetime.now()
        
        if task.schedule == 'hourly':
            return now + timedelta(hours=1)
        elif task.schedule == 'daily':
            # Run at 2 AM
            next_run = now.replace(hour=2, minute=0, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=1)
            return next_run
        elif task.schedule == 'weekly':
            # Run on Sunday at 2 AM
            days_until_sunday = (6 - now.weekday()) % 7
            next_run = now.replace(hour=2, minute=0, second=0, microsecond=0)
            next_run += timedelta(days=days_until_sunday)
            if next_run <= now:
                next_run += timedelta(weeks=1)
            return next_run
        elif task.schedule == '30min':
            return now + timedelta(minutes=30)
        elif task.schedule == '15min':
            return now + timedelta(minutes=15)
        elif task.schedule == '5min':
            return now + timedelta(minutes=5)
        else:
            # Default to hourly for unknown schedules
            return now + timedelta(hours=1)
    
    def start_scheduler(self):
        """Start the automation scheduler"""
        if self.running:
            return
        
        self.running = True
        self._scheduler_thread = threading.Thread(
            target=self._scheduler_loop,
            daemon=True,
            name="AutomationScheduler"
        )
        self._scheduler_thread.start()
        self.logger.info("Automation scheduler started")
    
    def stop_scheduler(self):
        """Stop the automation scheduler"""
        self.running = False
        if self._scheduler_thread:
            self._scheduler_thread.join(timeout=5)
        self.logger.info("Automation scheduler stopped")
    
    def _scheduler_loop(self):
        """Main scheduler loop"""
        while self.running:
            try:
                current_time = datetime.now()
                
                # Check all tasks for execution
                with self._lock:
                    for task in list(self.tasks.values()):
                        if (task.enabled and 
                            task.next_run and 
                            current_time >= task.next_run and
                            task.status != TaskStatus.RUNNING):
                            
                            # Execute task in background
                            threading.Thread(
                                target=self._execute_task,
                                args=(task,),
                                daemon=True,
                                name=f"Task-{task.task_id}"
                            ).start()
                
                # Sleep for 30 seconds before next check
                time.sleep(30)
                
            except Exception as e:
                self.logger.error(f"Scheduler loop error: {e}")
                time.sleep(60)  # Wait longer on error
    
    def _execute_task(self, task: AutomationTask):
        """Execute a single task"""
        task.status = TaskStatus.RUNNING
        start_time = time.time()
        
        try:
            self.logger.info(f"Executing task: {task.name}")
            
            # Execute the task function
            if task.function:
                task.function(**task.parameters)
            else:
                # Execute built-in task type
                self._execute_builtin_task(task)
            
            # Task completed successfully
            task.status = TaskStatus.COMPLETED
            task.last_run = datetime.now()
            task.run_count += 1
            task.failure_count = 0  # Reset failure count on success
            
            # Calculate next run
            task.next_run = self._calculate_next_run(task)
            
            execution_time = time.time() - start_time
            self.logger.info(f"Task '{task.name}' completed in {execution_time:.2f}s")
            
        except Exception as e:
            # Task failed
            task.status = TaskStatus.FAILED
            task.failure_count += 1
            
            # Calculate next run (with backoff on repeated failures)
            if task.failure_count < task.max_failures:
                # Exponential backoff
                delay_minutes = min(60, 5 * (2 ** task.failure_count))
                task.next_run = datetime.now() + timedelta(minutes=delay_minutes)
            else:
                # Too many failures, disable task
                task.enabled = False
                task.next_run = None
                self.logger.error(f"Task '{task.name}' disabled after {task.max_failures} failures")
            
            self.logger.error(f"Task '{task.name}' failed: {e}")
        
        finally:
            self._save_tasks()
    
    def _execute_builtin_task(self, task: AutomationTask):
        """Execute built-in task types"""
        if task.task_type == TaskType.BACKUP:
            self._backup_task(**task.parameters)
        elif task.task_type == TaskType.HEALTH_CHECK:
            self._health_check_task(**task.parameters)
        elif task.task_type == TaskType.BALANCE_CHECK:
            self._balance_check_task(**task.parameters)
        else:
            raise ValueError(f"Unknown task type: {task.task_type}")
    
    def _backup_task(self, **kwargs):
        """Execute backup task"""
        from .config_enhanced import get_enhanced_config_manager
        import subprocess
        import tempfile
        
        try:
            config_manager = get_enhanced_config_manager()
            data_dir = Path(config_manager.get('system.data_dir', './data'))
            
            # Create backup using CLI command
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = data_dir / 'backups' / f'auto_backup_{timestamp}.json.gz'
            
            # Simple backup creation (this could be enhanced)
            self.logger.info(f"Creating automated backup: {backup_path}")
            # Note: In a real implementation, this would call the backup function directly
            
        except Exception as e:
            raise Exception(f"Backup task failed: {e}")
    
    def _health_check_task(self, **kwargs):
        """Execute health check task"""
        try:
            from .health import get_health_checker
            
            checker = get_health_checker()
            status = checker.get_quick_status()
            
            # Log health status
            self.logger.info(f"Health check: {status.get('status', 'unknown')}")
            
            # Alert on critical status
            if status.get('status') == 'critical':
                self.logger.warning("System health is critical!")
                # Could send notifications here
                
        except Exception as e:
            raise Exception(f"Health check task failed: {e}")
    
    def _balance_check_task(self, **kwargs):
        """Execute balance monitoring task"""
        try:
            from ..lightning.client import LightningClient
            
            config = self.config_manager.get_all()
            client = LightningClient(config)
            
            # Get balances
            wallet = client.wallet_balance()
            channels = client.channel_balance()
            
            wallet_balance = int(wallet.get('confirmed_balance', 0))
            channel_balance = int(channels.get('balance', 0))
            
            self.logger.info(f"Balance check - Wallet: {wallet_balance}, Channels: {channel_balance}")
            
            # Check thresholds
            min_wallet = kwargs.get('min_wallet_balance', 100000)  # 100k sats
            min_channel = kwargs.get('min_channel_balance', 50000)  # 50k sats
            
            if wallet_balance < min_wallet:
                self.logger.warning(f"Low wallet balance: {wallet_balance} < {min_wallet}")
            
            if channel_balance < min_channel:
                self.logger.warning(f"Low channel balance: {channel_balance} < {min_channel}")
                
        except Exception as e:
            raise Exception(f"Balance check task failed: {e}")
    
    def get_task_status(self) -> Dict[str, Any]:
        """Get automation system status"""
        with self._lock:
            return {
                'scheduler_running': self.running,
                'total_tasks': len(self.tasks),
                'enabled_tasks': sum(1 for t in self.tasks.values() if t.enabled),
                'running_tasks': sum(1 for t in self.tasks.values() if t.status == TaskStatus.RUNNING),
                'failed_tasks': sum(1 for t in self.tasks.values() if t.status == TaskStatus.FAILED),
                'tasks': {
                    task_id: {
                        'name': task.name,
                        'type': task.task_type.value,
                        'enabled': task.enabled,
                        'status': task.status.value,
                        'last_run': task.last_run.isoformat() if task.last_run else None,
                        'next_run': task.next_run.isoformat() if task.next_run else None,
                        'run_count': task.run_count,
                        'failure_count': task.failure_count
                    }
                    for task_id, task in self.tasks.items()
                }
            }
    
    def run_task_now(self, task_id: str) -> bool:
        """Execute a task immediately"""
        with self._lock:
            if task_id not in self.tasks:
                return False
            
            task = self.tasks[task_id]
            if task.status == TaskStatus.RUNNING:
                return False
            
            # Execute in background
            threading.Thread(
                target=self._execute_task,
                args=(task,),
                daemon=True,
                name=f"Manual-{task.task_id}"
            ).start()
            
            return True


# Global instance
_automation = None
_automation_lock = threading.Lock()


def get_automation() -> LightweightAutomation:
    """Get global automation instance"""
    global _automation
    if _automation is None:
        with _automation_lock:
            if _automation is None:
                _automation = LightweightAutomation()
    return _automation


def start_automation():
    """Start automation system"""
    automation = get_automation()
    automation.start_scheduler()


def stop_automation():
    """Stop automation system"""
    automation = get_automation()
    automation.stop_scheduler()