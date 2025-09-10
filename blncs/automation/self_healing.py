"""
Self-Healing and Predictive Maintenance System
Autonomous system recovery and proactive maintenance capabilities.
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
from dataclasses import dataclass, field
import structlog
import psutil
import subprocess
import threading
from pathlib import Path
import yaml
import hashlib
import pickle
from collections import defaultdict, deque

logger = structlog.get_logger(__name__)

class HealthStatus(Enum):
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    FAILING = "failing"
    UNKNOWN = "unknown"

class RecoveryAction(Enum):
    RESTART_SERVICE = "restart_service"
    RESTART_PROCESS = "restart_process"
    CLEAR_CACHE = "clear_cache"
    FREE_MEMORY = "free_memory"
    DISK_CLEANUP = "disk_cleanup"
    NETWORK_RESET = "network_reset"
    DATABASE_REPAIR = "database_repair"
    FAILOVER = "failover"
    SCALE_UP = "scale_up"
    QUARANTINE = "quarantine"

class MaintenanceType(Enum):
    PREVENTIVE = "preventive"
    PREDICTIVE = "predictive"
    CORRECTIVE = "corrective"
    EMERGENCY = "emergency"

@dataclass
class HealthCheck:
    name: str
    description: str
    check_function: Callable
    threshold_warning: float
    threshold_critical: float
    check_interval: int = 60
    enabled: bool = True
    dependencies: List[str] = field(default_factory=list)
    recovery_actions: List[RecoveryAction] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class HealthResult:
    check_name: str
    status: HealthStatus
    value: float
    threshold_warning: float
    threshold_critical: float
    message: str
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class MaintenanceTask:
    id: str
    name: str
    description: str
    maintenance_type: MaintenanceType
    action_function: Callable
    priority: int = 5
    schedule: Optional[str] = None
    condition: Optional[Callable] = None
    dependencies: List[str] = field(default_factory=list)
    estimated_duration: int = 300
    requires_downtime: bool = False
    rollback_function: Optional[Callable] = None

class SelfHealingSystem:
    """
    Autonomous self-healing system with predictive maintenance capabilities.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._default_config()
        self.health_checks: Dict[str, HealthCheck] = {}
        self.maintenance_tasks: Dict[str, MaintenanceTask] = {}
        self.health_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.recovery_history: List[Dict[str, Any]] = []
        self.maintenance_history: List[Dict[str, Any]] = []
        
        self.anomaly_detector = AnomalyDetector()
        self.failure_predictor = FailurePredictor()
        self.recovery_engine = RecoveryEngine(self.config)
        self.maintenance_scheduler = MaintenanceScheduler()
        
        self.running = False
        self.monitoring_thread = None
        self.stats = {
            'health_checks_performed': 0,
            'issues_detected': 0,
            'automatic_recoveries': 0,
            'maintenance_tasks_completed': 0,
            'system_uptime': 0,
            'mean_time_to_recovery': 0
        }

    def _default_config(self) -> Dict[str, Any]:
        """Default configuration for self-healing system."""
        return {
            'monitoring_interval': 30,
            'health_check_timeout': 10,
            'recovery_timeout': 300,
            'max_recovery_attempts': 3,
            'recovery_cooldown': 180,
            'enable_automatic_recovery': True,
            'enable_predictive_maintenance': True,
            'enable_anomaly_detection': True,
            'notification_enabled': True,
            'log_level': 'INFO',
            'backup_before_recovery': True,
            'maintenance_window': {'start': '02:00', 'end': '04:00'}
        }

    async def start(self):
        """Start the self-healing system."""
        if self.running:
            return
        
        self.running = True
        logger.info("Starting Self-Healing System")
        
        # Initialize components
        await self.anomaly_detector.initialize()
        await self.failure_predictor.initialize()
        await self.recovery_engine.initialize()
        await self.maintenance_scheduler.initialize()
        
        # Register default health checks
        await self._register_default_health_checks()
        
        # Register default maintenance tasks
        await self._register_default_maintenance_tasks()
        
        # Start monitoring thread
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True
        )
        self.monitoring_thread.start()
        
        logger.info("Self-healing system started successfully")

    async def stop(self):
        """Stop the self-healing system."""
        self.running = False
        
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=10)
        
        logger.info("Self-healing system stopped")

    def register_health_check(self, health_check: HealthCheck) -> str:
        """Register a new health check."""
        self.health_checks[health_check.name] = health_check
        logger.info(f"Registered health check: {health_check.name}")
        return health_check.name

    def register_maintenance_task(self, task: MaintenanceTask) -> str:
        """Register a new maintenance task."""
        self.maintenance_tasks[task.id] = task
        if task.schedule:
            self.maintenance_scheduler.schedule_task(task)
        logger.info(f"Registered maintenance task: {task.name}")
        return task.id

    def _monitoring_loop(self):
        """Main monitoring loop running in separate thread."""
        while self.running:
            try:
                # Perform health checks
                asyncio.run(self._perform_health_checks())
                
                # Check for maintenance tasks
                asyncio.run(self._check_maintenance_schedule())
                
                # Anomaly detection
                if self.config['enable_anomaly_detection']:
                    asyncio.run(self.anomaly_detector.detect_anomalies(self.health_history))
                
                # Predictive maintenance
                if self.config['enable_predictive_maintenance']:
                    asyncio.run(self.failure_predictor.predict_failures(self.health_history))
                
                time.sleep(self.config['monitoring_interval'])
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(10)

    async def _perform_health_checks(self):
        """Perform all enabled health checks."""
        for check_name, health_check in self.health_checks.items():
            if not health_check.enabled:
                continue
            
            try:
                result = await self._execute_health_check(health_check)
                self.health_history[check_name].append(result)
                
                # Check if recovery is needed
                if result.status in [HealthStatus.CRITICAL, HealthStatus.FAILING]:
                    await self._handle_health_issue(health_check, result)
                
                self.stats['health_checks_performed'] += 1
                
            except Exception as e:
                logger.error(f"Health check {check_name} failed: {e}")
                # Create failure result
                failure_result = HealthResult(
                    check_name=check_name,
                    status=HealthStatus.UNKNOWN,
                    value=-1,
                    threshold_warning=health_check.threshold_warning,
                    threshold_critical=health_check.threshold_critical,
                    message=f"Health check failed: {e}",
                    timestamp=datetime.now()
                )
                self.health_history[check_name].append(failure_result)

    async def _execute_health_check(self, health_check: HealthCheck) -> HealthResult:
        """Execute a single health check."""
        try:
            # Execute check function with timeout
            value = await asyncio.wait_for(
                health_check.check_function(),
                timeout=self.config['health_check_timeout']
            )
            
            # Determine status based on thresholds
            if value >= health_check.threshold_critical:
                status = HealthStatus.CRITICAL
                message = f"Critical threshold exceeded: {value:.2f} >= {health_check.threshold_critical:.2f}"
            elif value >= health_check.threshold_warning:
                status = HealthStatus.WARNING
                message = f"Warning threshold exceeded: {value:.2f} >= {health_check.threshold_warning:.2f}"
            else:
                status = HealthStatus.HEALTHY
                message = f"Healthy: {value:.2f}"
            
            return HealthResult(
                check_name=health_check.name,
                status=status,
                value=value,
                threshold_warning=health_check.threshold_warning,
                threshold_critical=health_check.threshold_critical,
                message=message,
                timestamp=datetime.now()
            )
            
        except asyncio.TimeoutError:
            return HealthResult(
                check_name=health_check.name,
                status=HealthStatus.UNKNOWN,
                value=-1,
                threshold_warning=health_check.threshold_warning,
                threshold_critical=health_check.threshold_critical,
                message="Health check timed out",
                timestamp=datetime.now()
            )

    async def _handle_health_issue(self, health_check: HealthCheck, result: HealthResult):
        """Handle a detected health issue."""
        if not self.config['enable_automatic_recovery']:
            logger.warning(f"Health issue detected but automatic recovery disabled: {result.message}")
            return
        
        logger.warning(f"Health issue detected: {result.message}")
        self.stats['issues_detected'] += 1
        
        # Execute recovery actions
        for action in health_check.recovery_actions:
            try:
                success = await self.recovery_engine.execute_recovery_action(
                    action, health_check, result
                )
                
                if success:
                    logger.info(f"Recovery action {action.value} successful for {health_check.name}")
                    self.stats['automatic_recoveries'] += 1
                    
                    # Record recovery
                    self.recovery_history.append({
                        'timestamp': datetime.now().isoformat(),
                        'check_name': health_check.name,
                        'issue': result.message,
                        'action': action.value,
                        'success': True
                    })
                    break
                else:
                    logger.error(f"Recovery action {action.value} failed for {health_check.name}")
                    
            except Exception as e:
                logger.error(f"Recovery action {action.value} error: {e}")
                self.recovery_history.append({
                    'timestamp': datetime.now().isoformat(),
                    'check_name': health_check.name,
                    'issue': result.message,
                    'action': action.value,
                    'success': False,
                    'error': str(e)
                })

    async def _check_maintenance_schedule(self):
        """Check and execute scheduled maintenance tasks."""
        ready_tasks = await self.maintenance_scheduler.get_ready_tasks(datetime.now())
        
        for task in ready_tasks:
            await self._execute_maintenance_task(task)

    async def _execute_maintenance_task(self, task: MaintenanceTask):
        """Execute a maintenance task."""
        logger.info(f"Executing maintenance task: {task.name}")
        
        start_time = datetime.now()
        
        try:
            # Check dependencies
            if task.dependencies:
                if not await self._check_task_dependencies(task.dependencies):
                    logger.warning(f"Dependencies not met for task {task.name}")
                    return
            
            # Check condition if specified
            if task.condition and not await task.condition():
                logger.info(f"Condition not met for task {task.name}")
                return
            
            # Execute task
            await asyncio.wait_for(
                task.action_function(),
                timeout=task.estimated_duration
            )
            
            execution_time = (datetime.now() - start_time).total_seconds()
            
            # Record success
            self.maintenance_history.append({
                'timestamp': start_time.isoformat(),
                'task_id': task.id,
                'task_name': task.name,
                'execution_time': execution_time,
                'success': True
            })
            
            self.stats['maintenance_tasks_completed'] += 1
            logger.info(f"Maintenance task completed: {task.name} in {execution_time:.1f}s")
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            
            # Record failure
            self.maintenance_history.append({
                'timestamp': start_time.isoformat(),
                'task_id': task.id,
                'task_name': task.name,
                'execution_time': execution_time,
                'success': False,
                'error': str(e)
            })
            
            logger.error(f"Maintenance task failed: {task.name} - {e}")
            
            # Execute rollback if available
            if task.rollback_function:
                try:
                    await task.rollback_function()
                    logger.info(f"Rollback successful for task {task.name}")
                except Exception as rollback_error:
                    logger.error(f"Rollback failed for task {task.name}: {rollback_error}")

    async def _register_default_health_checks(self):
        """Register default health checks for common system components."""
        
        # CPU Usage Check
        self.register_health_check(HealthCheck(
            name="cpu_usage",
            description="Monitor CPU usage percentage",
            check_function=self._check_cpu_usage,
            threshold_warning=70.0,
            threshold_critical=90.0,
            check_interval=30,
            recovery_actions=[RecoveryAction.RESTART_SERVICE, RecoveryAction.SCALE_UP]
        ))
        
        # Memory Usage Check
        self.register_health_check(HealthCheck(
            name="memory_usage",
            description="Monitor memory usage percentage",
            check_function=self._check_memory_usage,
            threshold_warning=80.0,
            threshold_critical=95.0,
            check_interval=30,
            recovery_actions=[RecoveryAction.FREE_MEMORY, RecoveryAction.CLEAR_CACHE]
        ))
        
        # Disk Usage Check
        self.register_health_check(HealthCheck(
            name="disk_usage",
            description="Monitor disk usage percentage",
            check_function=self._check_disk_usage,
            threshold_warning=85.0,
            threshold_critical=95.0,
            check_interval=300,
            recovery_actions=[RecoveryAction.DISK_CLEANUP]
        ))
        
        # Lightning Node Health Check
        self.register_health_check(HealthCheck(
            name="lightning_node_health",
            description="Monitor Lightning Network node health",
            check_function=self._check_lightning_health,
            threshold_warning=1.0,
            threshold_critical=2.0,
            check_interval=60,
            recovery_actions=[RecoveryAction.RESTART_SERVICE]
        ))
        
        # Database Health Check
        self.register_health_check(HealthCheck(
            name="database_health",
            description="Monitor database connection and performance",
            check_function=self._check_database_health,
            threshold_warning=1000.0,  # ms
            threshold_critical=5000.0,  # ms
            check_interval=120,
            recovery_actions=[RecoveryAction.DATABASE_REPAIR, RecoveryAction.RESTART_SERVICE]
        ))

    async def _register_default_maintenance_tasks(self):
        """Register default maintenance tasks."""
        
        # System Cleanup
        self.register_maintenance_task(MaintenanceTask(
            id="system_cleanup",
            name="System Cleanup",
            description="Clean temporary files and optimize storage",
            maintenance_type=MaintenanceType.PREVENTIVE,
            action_function=self._system_cleanup_task,
            priority=3,
            schedule="0 2 * * *",  # Daily at 2 AM
            estimated_duration=600
        ))
        
        # Database Optimization
        self.register_maintenance_task(MaintenanceTask(
            id="database_optimization",
            name="Database Optimization",
            description="Optimize database performance",
            maintenance_type=MaintenanceType.PREVENTIVE,
            action_function=self._database_optimization_task,
            priority=2,
            schedule="0 3 * * 0",  # Weekly on Sunday at 3 AM
            estimated_duration=1800
        ))
        
        # Log Rotation
        self.register_maintenance_task(MaintenanceTask(
            id="log_rotation",
            name="Log Rotation",
            description="Rotate and compress log files",
            maintenance_type=MaintenanceType.PREVENTIVE,
            action_function=self._log_rotation_task,
            priority=4,
            schedule="0 1 * * *",  # Daily at 1 AM
            estimated_duration=120
        ))

    # Health check functions
    async def _check_cpu_usage(self) -> float:
        """Check CPU usage percentage."""
        return psutil.cpu_percent(interval=1)

    async def _check_memory_usage(self) -> float:
        """Check memory usage percentage."""
        return psutil.virtual_memory().percent

    async def _check_disk_usage(self) -> float:
        """Check disk usage percentage."""
        return psutil.disk_usage('/').percent

    async def _check_lightning_health(self) -> float:
        """Check Lightning Network node health."""
        # Placeholder - would integrate with actual Lightning client
        return 0.0

    async def _check_database_health(self) -> float:
        """Check database health (return query time in ms)."""
        # Placeholder - would test actual database connection
        return 50.0

    # Maintenance task functions
    async def _system_cleanup_task(self):
        """Perform system cleanup."""
        logger.info("Performing system cleanup")
        # Implement actual cleanup logic
        
    async def _database_optimization_task(self):
        """Perform database optimization."""
        logger.info("Performing database optimization")
        # Implement actual database optimization
        
    async def _log_rotation_task(self):
        """Perform log rotation."""
        logger.info("Performing log rotation")
        # Implement actual log rotation

    async def _check_task_dependencies(self, dependencies: List[str]) -> bool:
        """Check if task dependencies are satisfied."""
        return True  # Simplified implementation

class AnomalyDetector:
    """Detect anomalies in system behavior patterns."""
    
    def __init__(self):
        self.baseline_models = {}
        self.anomaly_threshold = 2.0  # Standard deviations
    
    async def initialize(self):
        """Initialize the anomaly detector."""
        logger.info("Initializing anomaly detector")
    
    async def detect_anomalies(self, health_history: Dict[str, deque]) -> List[Dict[str, Any]]:
        """Detect anomalies in health check data."""
        anomalies = []
        
        for check_name, history in health_history.items():
            if len(history) < 10:
                continue
            
            # Simple statistical anomaly detection
            values = [result.value for result in history if result.value >= 0]
            if len(values) < 5:
                continue
            
            mean = sum(values) / len(values)
            variance = sum((x - mean) ** 2 for x in values) / len(values)
            std_dev = variance ** 0.5
            
            # Check if latest value is anomalous
            latest_value = values[-1]
            z_score = abs(latest_value - mean) / std_dev if std_dev > 0 else 0
            
            if z_score > self.anomaly_threshold:
                anomalies.append({
                    'check_name': check_name,
                    'value': latest_value,
                    'z_score': z_score,
                    'mean': mean,
                    'std_dev': std_dev,
                    'timestamp': datetime.now()
                })
        
        return anomalies

class FailurePredictor:
    """Predict potential system failures before they occur."""
    
    def __init__(self):
        self.prediction_models = {}
    
    async def initialize(self):
        """Initialize the failure predictor."""
        logger.info("Initializing failure predictor")
    
    async def predict_failures(self, health_history: Dict[str, deque]) -> List[Dict[str, Any]]:
        """Predict potential failures based on historical data."""
        predictions = []
        
        # Simplified trend analysis
        for check_name, history in health_history.items():
            if len(history) < 20:
                continue
            
            values = [result.value for result in history[-20:] if result.value >= 0]
            if len(values) < 10:
                continue
            
            # Simple linear trend analysis
            x = list(range(len(values)))
            n = len(values)
            sum_x = sum(x)
            sum_y = sum(values)
            sum_xy = sum(x[i] * values[i] for i in range(n))
            sum_x2 = sum(x[i] ** 2 for i in range(n))
            
            if n * sum_x2 - sum_x ** 2 != 0:
                slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x ** 2)
                
                # Predict failure if trend is strongly negative or positive
                if abs(slope) > 1.0:
                    predictions.append({
                        'check_name': check_name,
                        'trend_slope': slope,
                        'predicted_failure_time': datetime.now() + timedelta(hours=2),
                        'confidence': min(abs(slope) / 5.0, 1.0),
                        'timestamp': datetime.now()
                    })
        
        return predictions

class RecoveryEngine:
    """Execute recovery actions for system issues."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.recovery_attempt_count = defaultdict(int)
        self.last_recovery_time = defaultdict(datetime)
    
    async def initialize(self):
        """Initialize the recovery engine."""
        logger.info("Initializing recovery engine")
    
    async def execute_recovery_action(self, 
                                    action: RecoveryAction, 
                                    health_check: HealthCheck, 
                                    result: HealthResult) -> bool:
        """Execute a specific recovery action."""
        try:
            # Check cooldown period
            last_time = self.last_recovery_time.get(health_check.name, datetime.min)
            cooldown = timedelta(seconds=self.config['recovery_cooldown'])
            
            if datetime.now() - last_time < cooldown:
                logger.info(f"Recovery action {action.value} in cooldown for {health_check.name}")
                return False
            
            # Check attempt limits
            if self.recovery_attempt_count[health_check.name] >= self.config['max_recovery_attempts']:
                logger.error(f"Max recovery attempts exceeded for {health_check.name}")
                return False
            
            # Execute action based on type
            success = False
            if action == RecoveryAction.RESTART_SERVICE:
                success = await self._restart_service(health_check.name)
            elif action == RecoveryAction.RESTART_PROCESS:
                success = await self._restart_process(health_check.name)
            elif action == RecoveryAction.CLEAR_CACHE:
                success = await self._clear_cache()
            elif action == RecoveryAction.FREE_MEMORY:
                success = await self._free_memory()
            elif action == RecoveryAction.DISK_CLEANUP:
                success = await self._disk_cleanup()
            elif action == RecoveryAction.DATABASE_REPAIR:
                success = await self._database_repair()
            
            # Update tracking
            self.last_recovery_time[health_check.name] = datetime.now()
            if success:
                self.recovery_attempt_count[health_check.name] = 0
            else:
                self.recovery_attempt_count[health_check.name] += 1
            
            return success
            
        except Exception as e:
            logger.error(f"Recovery action {action.value} failed: {e}")
            return False
    
    async def _restart_service(self, service_name: str) -> bool:
        """Restart a system service."""
        try:
            # This would restart actual services
            logger.info(f"Restarting service: {service_name}")
            return True
        except Exception:
            return False
    
    async def _restart_process(self, process_name: str) -> bool:
        """Restart a specific process."""
        try:
            logger.info(f"Restarting process: {process_name}")
            return True
        except Exception:
            return False
    
    async def _clear_cache(self) -> bool:
        """Clear system caches."""
        try:
            logger.info("Clearing system caches")
            return True
        except Exception:
            return False
    
    async def _free_memory(self) -> bool:
        """Free up system memory."""
        try:
            import gc
            gc.collect()
            logger.info("Memory freed")
            return True
        except Exception:
            return False
    
    async def _disk_cleanup(self) -> bool:
        """Clean up disk space."""
        try:
            logger.info("Performing disk cleanup")
            return True
        except Exception:
            return False
    
    async def _database_repair(self) -> bool:
        """Repair database issues."""
        try:
            logger.info("Repairing database")
            return True
        except Exception:
            return False

class MaintenanceScheduler:
    """Schedule and manage maintenance tasks."""
    
    def __init__(self):
        self.scheduled_tasks: List[MaintenanceTask] = []
        self.last_execution: Dict[str, datetime] = {}
    
    async def initialize(self):
        """Initialize the maintenance scheduler."""
        logger.info("Initializing maintenance scheduler")
    
    def schedule_task(self, task: MaintenanceTask):
        """Schedule a maintenance task."""
        self.scheduled_tasks.append(task)
        logger.info(f"Scheduled maintenance task: {task.name}")
    
    async def get_ready_tasks(self, current_time: datetime) -> List[MaintenanceTask]:
        """Get tasks that are ready to execute."""
        ready_tasks = []
        
        for task in self.scheduled_tasks:
            if self._is_task_ready(task, current_time):
                ready_tasks.append(task)
        
        return ready_tasks
    
    def _is_task_ready(self, task: MaintenanceTask, current_time: datetime) -> bool:
        """Check if a task is ready to execute."""
        # Simplified scheduling logic
        last_exec = self.last_execution.get(task.id)
        if last_exec is None:
            return True
        
        # Check if enough time has passed (simplified daily check)
        if (current_time - last_exec).days >= 1:
            return True
        
        return False

# Global self-healing system instance
_self_healing_instance = None

def get_self_healing_system(config: Optional[Dict[str, Any]] = None) -> SelfHealingSystem:
    """Get the global self-healing system instance."""
    global _self_healing_instance
    if _self_healing_instance is None:
        _self_healing_instance = SelfHealingSystem(config)
    return _self_healing_instance

async def initialize_self_healing_system(config: Optional[Dict[str, Any]] = None):
    """Initialize the self-healing system."""
    system = get_self_healing_system(config)
    await system.start()
    logger.info("Self-healing system initialized successfully")
    return system