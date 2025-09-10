"""
Intelligent Automation Orchestrator
Advanced automation system for maximum efficiency and minimal human intervention.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Callable
from enum import Enum
from dataclasses import dataclass, field
import structlog
from pathlib import Path
import importlib
import inspect
import yaml
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import threading
from queue import Queue, PriorityQueue
import time
import psutil
import schedule

logger = structlog.get_logger(__name__)

class AutomationType(Enum):
    MONITORING = "monitoring"
    MAINTENANCE = "maintenance"
    SCALING = "scaling"
    OPTIMIZATION = "optimization"
    DEPLOYMENT = "deployment"
    BACKUP = "backup"
    SECURITY = "security"
    RECOVERY = "recovery"
    ANALYTICS = "analytics"
    WORKFLOW = "workflow"

class Priority(Enum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    BACKGROUND = 5

class ExecutionMode(Enum):
    IMMEDIATE = "immediate"
    SCHEDULED = "scheduled"
    TRIGGERED = "triggered"
    CONTINUOUS = "continuous"
    ADAPTIVE = "adaptive"

@dataclass
class AutomationTask:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    task_type: AutomationType = AutomationType.WORKFLOW
    priority: Priority = Priority.MEDIUM
    execution_mode: ExecutionMode = ExecutionMode.IMMEDIATE
    function: Optional[Callable] = None
    params: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    triggers: List[str] = field(default_factory=list)
    schedule: Optional[str] = None
    timeout: int = 300
    retry_count: int = 3
    retry_delay: int = 5
    max_concurrent: int = 1
    resource_requirements: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    last_executed: Optional[datetime] = None
    success_count: int = 0
    failure_count: int = 0
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

class IntelligentOrchestrator:
    """
    Advanced automation orchestrator with AI-driven optimization.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.tasks: Dict[str, AutomationTask] = {}
        self.task_queue = PriorityQueue()
        self.running_tasks: Dict[str, asyncio.Task] = {}
        self.execution_history: List[Dict[str, Any]] = []
        self.resource_monitor = ResourceMonitor()
        self.scheduler = AdvancedScheduler()
        self.workflow_engine = WorkflowEngine()
        self.dependency_resolver = DependencyResolver()
        self.performance_optimizer = PerformanceOptimizer()
        self.executor = ThreadPoolExecutor(max_workers=self.config.get('max_workers', 10))
        self.running = False
        self.stats = {
            'tasks_executed': 0,
            'tasks_succeeded': 0,
            'tasks_failed': 0,
            'average_execution_time': 0,
            'resource_efficiency': 0
        }

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration from file or use defaults."""
        default_config = {
            'max_workers': 10,
            'max_memory_usage': 0.8,
            'max_cpu_usage': 0.7,
            'cleanup_interval': 3600,
            'health_check_interval': 60,
            'optimization_interval': 300,
            'log_level': 'INFO',
            'enable_learning': True,
            'enable_prediction': True,
            'enable_auto_scaling': True
        }
        
        if config_path and Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                        user_config = yaml.safe_load(f)
                    else:
                        user_config = json.load(f)
                default_config.update(user_config)
            except Exception as e:
                logger.warning(f"Failed to load config from {config_path}: {e}")
        
        return default_config

    async def start(self):
        """Start the automation orchestrator."""
        if self.running:
            return
        
        self.running = True
        logger.info("Starting Intelligent Automation Orchestrator")
        
        # Start background services
        asyncio.create_task(self._task_executor())
        asyncio.create_task(self._resource_monitor())
        asyncio.create_task(self._health_monitor())
        asyncio.create_task(self._performance_optimizer())
        asyncio.create_task(self._cleanup_service())
        
        # Initialize automation tasks
        await self._initialize_core_automations()
        
        logger.info("Automation orchestrator started successfully")

    async def stop(self):
        """Stop the automation orchestrator."""
        self.running = False
        
        # Cancel running tasks
        for task in self.running_tasks.values():
            task.cancel()
        
        # Shutdown executors
        self.executor.shutdown(wait=True)
        
        logger.info("Automation orchestrator stopped")

    def register_task(self, task: AutomationTask) -> str:
        """Register a new automation task."""
        if not task.function:
            raise ValueError("Task must have a function")
        
        self.tasks[task.id] = task
        
        # Schedule if needed
        if task.execution_mode == ExecutionMode.SCHEDULED and task.schedule:
            self.scheduler.schedule_task(task)
        
        logger.info(f"Registered automation task: {task.name} ({task.id})")
        return task.id

    def unregister_task(self, task_id: str):
        """Unregister an automation task."""
        if task_id in self.tasks:
            task = self.tasks[task_id]
            self.scheduler.unschedule_task(task)
            del self.tasks[task_id]
            logger.info(f"Unregistered automation task: {task.name}")

    async def execute_task(self, task_id: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """Execute a specific task immediately."""
        if task_id not in self.tasks:
            raise ValueError(f"Task {task_id} not found")
        
        task = self.tasks[task_id]
        execution_params = task.params.copy()
        if params:
            execution_params.update(params)
        
        return await self._execute_task_internal(task, execution_params)

    async def _execute_task_internal(self, task: AutomationTask, params: Dict[str, Any]) -> Any:
        """Internal task execution with full monitoring and error handling."""
        execution_id = str(uuid.uuid4())
        start_time = datetime.now()
        
        logger.info(f"Executing task: {task.name} ({execution_id})")
        
        # Check dependencies
        if not await self.dependency_resolver.check_dependencies(task.dependencies):
            raise RuntimeError(f"Dependencies not met for task {task.name}")
        
        # Check resources
        if not self.resource_monitor.check_resources(task.resource_requirements):
            raise RuntimeError(f"Insufficient resources for task {task.name}")
        
        try:
            # Execute with timeout
            if asyncio.iscoroutinefunction(task.function):
                result = await asyncio.wait_for(
                    task.function(**params),
                    timeout=task.timeout
                )
            else:
                result = await asyncio.get_event_loop().run_in_executor(
                    self.executor,
                    lambda: task.function(**params)
                )
            
            # Update success metrics
            task.success_count += 1
            task.last_executed = datetime.now()
            self.stats['tasks_succeeded'] += 1
            
            # Log execution
            execution_time = (datetime.now() - start_time).total_seconds()
            self.execution_history.append({
                'task_id': task.id,
                'execution_id': execution_id,
                'start_time': start_time.isoformat(),
                'execution_time': execution_time,
                'status': 'success',
                'result_size': len(str(result)) if result else 0
            })
            
            logger.info(f"Task completed successfully: {task.name} in {execution_time:.2f}s")
            return result
            
        except Exception as e:
            # Update failure metrics
            task.failure_count += 1
            self.stats['tasks_failed'] += 1
            
            # Log failure
            execution_time = (datetime.now() - start_time).total_seconds()
            self.execution_history.append({
                'task_id': task.id,
                'execution_id': execution_id,
                'start_time': start_time.isoformat(),
                'execution_time': execution_time,
                'status': 'failed',
                'error': str(e)
            })
            
            logger.error(f"Task failed: {task.name} - {e}")
            
            # Retry if configured
            if task.retry_count > 0:
                await asyncio.sleep(task.retry_delay)
                task.retry_count -= 1
                return await self._execute_task_internal(task, params)
            
            raise

    async def _task_executor(self):
        """Main task execution loop."""
        while self.running:
            try:
                # Process scheduled tasks
                ready_tasks = self.scheduler.get_ready_tasks()
                for task in ready_tasks:
                    if task.enabled and task.id not in self.running_tasks:
                        asyncio.create_task(self._execute_task_internal(task, task.params))
                
                # Process queued tasks
                while not self.task_queue.empty():
                    priority, task_id = self.task_queue.get()
                    if task_id in self.tasks and task_id not in self.running_tasks:
                        task = self.tasks[task_id]
                        if task.enabled:
                            self.running_tasks[task_id] = asyncio.create_task(
                                self._execute_task_internal(task, task.params)
                            )
                
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"Error in task executor: {e}")
                await asyncio.sleep(5)

    async def _resource_monitor(self):
        """Monitor system resources and adjust automation accordingly."""
        while self.running:
            try:
                await self.resource_monitor.update_metrics()
                
                # Auto-scale based on resources
                if self.config.get('enable_auto_scaling'):
                    await self._auto_scale()
                
                await asyncio.sleep(self.config.get('health_check_interval', 60))
                
            except Exception as e:
                logger.error(f"Error in resource monitor: {e}")
                await asyncio.sleep(30)

    async def _auto_scale(self):
        """Automatically scale automation based on resource usage."""
        cpu_usage = psutil.cpu_percent()
        memory_usage = psutil.virtual_memory().percent / 100
        
        max_cpu = self.config.get('max_cpu_usage', 0.7)
        max_memory = self.config.get('max_memory_usage', 0.8)
        
        if cpu_usage > max_cpu or memory_usage > max_memory:
            # Scale down - pause low priority tasks
            for task in self.tasks.values():
                if task.priority in [Priority.LOW, Priority.BACKGROUND]:
                    task.enabled = False
            logger.info("Scaled down automation due to high resource usage")
        
        elif cpu_usage < max_cpu * 0.5 and memory_usage < max_memory * 0.5:
            # Scale up - enable paused tasks
            for task in self.tasks.values():
                if not task.enabled:
                    task.enabled = True
            logger.info("Scaled up automation due to low resource usage")

    async def _initialize_core_automations(self):
        """Initialize essential automation tasks."""
        
        # System Health Monitoring
        health_task = AutomationTask(
            name="System Health Monitor",
            description="Monitor system health and trigger alerts",
            task_type=AutomationType.MONITORING,
            priority=Priority.HIGH,
            execution_mode=ExecutionMode.CONTINUOUS,
            function=self._monitor_system_health,
            schedule="*/5 * * * *"  # Every 5 minutes
        )
        self.register_task(health_task)
        
        # Auto Cleanup
        cleanup_task = AutomationTask(
            name="System Cleanup",
            description="Clean up temporary files and optimize storage",
            task_type=AutomationType.MAINTENANCE,
            priority=Priority.MEDIUM,
            execution_mode=ExecutionMode.SCHEDULED,
            function=self._system_cleanup,
            schedule="0 2 * * *"  # Daily at 2 AM
        )
        self.register_task(cleanup_task)
        
        # Performance Optimization
        optimization_task = AutomationTask(
            name="Performance Optimizer",
            description="Optimize system performance automatically",
            task_type=AutomationType.OPTIMIZATION,
            priority=Priority.MEDIUM,
            execution_mode=ExecutionMode.SCHEDULED,
            function=self._optimize_performance,
            schedule="0 */6 * * *"  # Every 6 hours
        )
        self.register_task(optimization_task)
        
        # Auto Backup
        backup_task = AutomationTask(
            name="Automated Backup",
            description="Perform automated system backups",
            task_type=AutomationType.BACKUP,
            priority=Priority.HIGH,
            execution_mode=ExecutionMode.SCHEDULED,
            function=self._automated_backup,
            schedule="0 1 * * *"  # Daily at 1 AM
        )
        self.register_task(backup_task)

    async def _monitor_system_health(self):
        """Monitor overall system health."""
        # This would integrate with existing health monitoring
        pass

    async def _system_cleanup(self):
        """Perform automated system cleanup."""
        # This would integrate with existing cleanup systems
        pass

    async def _optimize_performance(self):
        """Optimize system performance automatically."""
        # This would integrate with existing optimization systems
        pass

    async def _automated_backup(self):
        """Perform automated backups."""
        # This would integrate with existing backup systems
        pass

class ResourceMonitor:
    """Monitor system resources for automation decisions."""
    
    def __init__(self):
        self.metrics = {}
    
    async def update_metrics(self):
        """Update current resource metrics."""
        self.metrics = {
            'cpu_percent': psutil.cpu_percent(),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': psutil.disk_usage('/').percent,
            'network_io': psutil.net_io_counters(),
            'timestamp': datetime.now()
        }
    
    def check_resources(self, requirements: Dict[str, Any]) -> bool:
        """Check if resources meet requirements."""
        if not requirements:
            return True
        
        cpu_req = requirements.get('cpu_percent', 0)
        memory_req = requirements.get('memory_percent', 0)
        
        current_cpu = self.metrics.get('cpu_percent', 100)
        current_memory = self.metrics.get('memory_percent', 100)
        
        return current_cpu + cpu_req <= 90 and current_memory + memory_req <= 90

class AdvancedScheduler:
    """Advanced task scheduler with cron-like functionality."""
    
    def __init__(self):
        self.scheduled_tasks: List[AutomationTask] = []
    
    def schedule_task(self, task: AutomationTask):
        """Schedule a task using cron-like syntax."""
        if task.schedule:
            self.scheduled_tasks.append(task)
            schedule.every().minute.do(self._check_scheduled_tasks)
    
    def unschedule_task(self, task: AutomationTask):
        """Unschedule a task."""
        if task in self.scheduled_tasks:
            self.scheduled_tasks.remove(task)
    
    def get_ready_tasks(self) -> List[AutomationTask]:
        """Get tasks ready for execution."""
        # This would implement proper cron parsing and scheduling
        return []
    
    def _check_scheduled_tasks(self):
        """Check which scheduled tasks are ready to run."""
        pass

class WorkflowEngine:
    """Execute complex workflows with dependencies."""
    
    def __init__(self):
        self.workflows: Dict[str, Any] = {}
    
    async def execute_workflow(self, workflow_id: str) -> Any:
        """Execute a workflow with proper dependency handling."""
        pass

class DependencyResolver:
    """Resolve task dependencies and execution order."""
    
    async def check_dependencies(self, dependencies: List[str]) -> bool:
        """Check if all dependencies are satisfied."""
        return True  # Simplified implementation
    
    def resolve_execution_order(self, tasks: List[AutomationTask]) -> List[AutomationTask]:
        """Resolve optimal execution order based on dependencies."""
        return tasks  # Simplified implementation

class PerformanceOptimizer:
    """Optimize automation performance using machine learning."""
    
    def __init__(self):
        self.learning_enabled = True
        self.performance_data = []
    
    async def optimize_task_scheduling(self, tasks: List[AutomationTask]):
        """Optimize task scheduling based on historical performance."""
        if not self.learning_enabled:
            return
        
        # This would implement ML-based optimization
        pass
    
    def learn_from_execution(self, execution_data: Dict[str, Any]):
        """Learn from task execution to improve future performance."""
        if self.learning_enabled:
            self.performance_data.append(execution_data)

# Global orchestrator instance
_orchestrator_instance = None

def get_orchestrator(config_path: Optional[str] = None) -> IntelligentOrchestrator:
    """Get the global orchestrator instance."""
    global _orchestrator_instance
    if _orchestrator_instance is None:
        _orchestrator_instance = IntelligentOrchestrator(config_path)
    return _orchestrator_instance

async def initialize_automation_system(config_path: Optional[str] = None):
    """Initialize the automation system."""
    orchestrator = get_orchestrator(config_path)
    await orchestrator.start()
    logger.info("Automation system initialized successfully")
    return orchestrator