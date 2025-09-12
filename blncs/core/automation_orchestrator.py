#!/usr/bin/env python3
"""
Unified Automation Orchestrator - 省力化の最大化
Centralizes and automates all repetitive tasks across BLNCS
"""

import asyncio
import threading
import time
from typing import Dict, List, Any, Callable, Optional, Union
from dataclasses import dataclass, field
from enum import Enum
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
import json
import inspect

# Use lightweight fallbacks instead of external dependencies
try:
    from blncs.utils.lightweight_fallbacks import get_system_monitor
    system_monitor = get_system_monitor()
except ImportError:
    system_monitor = None

logger = logging.getLogger(__name__)


class TaskPriority(Enum):
    LOW = 1
    NORMAL = 2  
    HIGH = 3
    CRITICAL = 4


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class AutomationTask:
    """統一されたタスク定義"""
    task_id: str
    name: str
    func: Callable
    args: tuple = ()
    kwargs: dict = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.NORMAL
    schedule: Optional[str] = None  # cron-like schedule
    retry_count: int = 3
    timeout: float = 300.0
    dependencies: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    
    # Runtime info
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Any = None
    error: Optional[Exception] = None
    execution_count: int = 0


class AutomationOrchestrator:
    """
    統一オートメーション・オーケストレータ
    
    機能:
    - 全システムタスクの統一管理
    - インテリジェント・スケジューリング
    - 依存関係解決
    - 自動リトライとエラー処理
    - リソース最適化
    - パフォーマンス監視
    """
    
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.tasks: Dict[str, AutomationTask] = {}
        self.task_queue: List[AutomationTask] = []
        self.running_tasks: Dict[str, asyncio.Task] = {}
        
        # Statistics
        self.stats = {
            'total_tasks': 0,
            'completed_tasks': 0,
            'failed_tasks': 0,
            'avg_execution_time': 0.0,
            'resource_usage': {
                'cpu_time': 0.0,
                'memory_peak': 0.0
            }
        }
        
        # Smart optimizations
        self.task_patterns = {}  # Learn from execution patterns
        self.resource_monitor = ResourceMonitor()
        self.dependency_resolver = DependencyResolver()
        
        # Event system
        self.event_handlers = {
            'task_started': [],
            'task_completed': [],
            'task_failed': [],
            'batch_completed': []
        }
        
        self._running = False
        self._loop_task = None
    
    def register_task(self, 
                     task_id: str,
                     func: Callable,
                     name: str = None,
                     priority: TaskPriority = TaskPriority.NORMAL,
                     schedule: str = None,
                     retry_count: int = 3,
                     timeout: float = 300.0,
                     dependencies: List[str] = None,
                     **kwargs) -> AutomationTask:
        """タスクを登録"""
        
        task = AutomationTask(
            task_id=task_id,
            name=name or func.__name__,
            func=func,
            priority=priority,
            schedule=schedule,
            retry_count=retry_count,
            timeout=timeout,
            dependencies=dependencies or [],
            context=kwargs
        )
        
        self.tasks[task_id] = task
        logger.info(f"🔧 Task registered: {task_id} ({task.name})")
        return task
    
    def submit_task(self, task_id: str, *args, **kwargs) -> str:
        """タスクを実行キューに追加"""
        if task_id not in self.tasks:
            raise ValueError(f"Unknown task: {task_id}")
        
        # Create task instance for execution
        task = self.tasks[task_id]
        execution_id = f"{task_id}_{int(time.time())}_{task.execution_count}"
        
        exec_task = AutomationTask(
            task_id=execution_id,
            name=task.name,
            func=task.func,
            args=args,
            kwargs=kwargs,
            priority=task.priority,
            retry_count=task.retry_count,
            timeout=task.timeout,
            dependencies=task.dependencies,
            context=task.context.copy()
        )
        
        # Start the orchestrator if not already running
        if not self._running:
            try:
                self.start()
            except RuntimeError:
                # Running outside async context - that's ok, will be started later
                pass
        
        self.task_queue.append(exec_task)
        self.tasks[execution_id] = exec_task
        
        # Sort queue by priority
        self.task_queue.sort(key=lambda t: t.priority.value, reverse=True)
        
        logger.info(f"📝 Task queued: {execution_id}")
        return execution_id
    
    async def execute_task(self, task: AutomationTask) -> Any:
        """個別タスク実行"""
        task.status = TaskStatus.RUNNING
        task.started_at = datetime.now()
        task.execution_count += 1
        
        self._emit_event('task_started', task)
        
        try:
            # Check dependencies
            if task.dependencies:
                await self._wait_for_dependencies(task)
            
            # Resource check
            if not self.resource_monitor.can_execute(task):
                await asyncio.sleep(1)  # Brief wait for resources
            
            # Execute with timeout
            if inspect.iscoroutinefunction(task.func):
                result = await asyncio.wait_for(
                    task.func(*task.args, **task.kwargs),
                    timeout=task.timeout
                )
            else:
                # Run in thread pool for blocking functions
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    self.executor,
                    lambda: task.func(*task.args, **task.kwargs)
                )
            
            task.result = result
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.now()
            
            # Update statistics
            self._update_stats(task)
            self._emit_event('task_completed', task)
            
            logger.info(f"✅ Task completed: {task.task_id} ({task.name})")
            return result
            
        except Exception as e:
            task.error = e
            task.status = TaskStatus.FAILED
            task.completed_at = datetime.now()
            
            logger.error(f"❌ Task failed: {task.task_id} - {e}")
            
            # Retry logic
            if task.execution_count < task.retry_count:
                logger.info(f"🔄 Retrying task: {task.task_id} (attempt {task.execution_count + 1})")
                await asyncio.sleep(2 ** task.execution_count)  # Exponential backoff
                return await self.execute_task(task)
            
            self._emit_event('task_failed', task)
            raise e
    
    async def _wait_for_dependencies(self, task: AutomationTask):
        """依存関係の解決を待機"""
        max_wait = 300  # 5 minutes max wait
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            ready = True
            for dep_id in task.dependencies:
                if dep_id not in self.tasks:
                    ready = False
                    break
                dep_task = self.tasks[dep_id]
                if dep_task.status != TaskStatus.COMPLETED:
                    ready = False
                    break
            
            if ready:
                return
            
            await asyncio.sleep(1)
        
        raise TimeoutError(f"Dependencies not met for task: {task.task_id}")
    
    def start(self):
        """オーケストレーターを開始"""
        if self._running:
            return
        
        self._running = True
        self._loop_task = asyncio.create_task(self._execution_loop())
        logger.info("🚀 Automation Orchestrator started")
    
    def stop(self):
        """オーケストレーターを停止"""
        self._running = False
        if self._loop_task:
            self._loop_task.cancel()
        logger.info("🛑 Automation Orchestrator stopped")
    
    async def _execution_loop(self):
        """メイン実行ループ"""
        while self._running:
            try:
                if self.task_queue:
                    # Get next task
                    task = self.task_queue.pop(0)
                    
                    # Check resource availability
                    if len(self.running_tasks) >= self.max_workers:
                        self.task_queue.insert(0, task)  # Put back
                        await asyncio.sleep(0.1)
                        continue
                    
                    # Start task execution
                    execution_task = asyncio.create_task(self.execute_task(task))
                    self.running_tasks[task.task_id] = execution_task
                    
                    # Clean up completed tasks
                    self._cleanup_completed_tasks()
                
                await asyncio.sleep(0.1)  # Brief sleep to prevent busy loop
                
            except Exception as e:
                logger.error(f"Error in execution loop: {e}")
                await asyncio.sleep(1)
    
    def _cleanup_completed_tasks(self):
        """完了したタスクをクリーンアップ"""
        completed = []
        for task_id, task in self.running_tasks.items():
            if task.done():
                completed.append(task_id)
        
        for task_id in completed:
            del self.running_tasks[task_id]
    
    def _update_stats(self, task: AutomationTask):
        """統計情報を更新"""
        self.stats['total_tasks'] += 1
        if task.status == TaskStatus.COMPLETED:
            self.stats['completed_tasks'] += 1
            
            # Update average execution time
            if task.started_at and task.completed_at:
                exec_time = (task.completed_at - task.started_at).total_seconds()
                current_avg = self.stats['avg_execution_time']
                n = self.stats['completed_tasks']
                self.stats['avg_execution_time'] = (current_avg * (n-1) + exec_time) / n
        
        elif task.status == TaskStatus.FAILED:
            self.stats['failed_tasks'] += 1
    
    def _emit_event(self, event_type: str, task: AutomationTask):
        """イベントを発火"""
        for handler in self.event_handlers.get(event_type, []):
            try:
                handler(task)
            except Exception as e:
                logger.error(f"Event handler error: {e}")
    
    def add_event_handler(self, event_type: str, handler: Callable):
        """イベントハンドラーを追加"""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        self.event_handlers[event_type].append(handler)
    
    def get_stats(self) -> Dict[str, Any]:
        """統計情報を取得"""
        return {
            **self.stats,
            'queue_size': len(self.task_queue),
            'running_tasks': len(self.running_tasks),
            'total_registered_tasks': len(self.tasks)
        }
    
    def get_task_status(self, task_id: str) -> Optional[TaskStatus]:
        """タスクのステータスを取得"""
        if task_id in self.tasks:
            return self.tasks[task_id].status
        return None
    
    # Built-in automation templates
    def create_batch_processor(self, items: List[Any], 
                              processor_func: Callable,
                              batch_size: int = 10,
                              parallel: bool = True) -> List[str]:
        """バッチ処理の自動化"""
        task_ids = []
        
        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]
            task_id = f"batch_{i//batch_size}_{int(time.time())}"
            
            if parallel:
                self.register_task(
                    task_id,
                    self._process_batch_parallel,
                    f"Batch {i//batch_size + 1}",
                    TaskPriority.NORMAL,
                    batch=batch,
                    processor_func=processor_func
                )
            else:
                self.register_task(
                    task_id,
                    self._process_batch_sequential,
                    f"Batch {i//batch_size + 1}",
                    TaskPriority.NORMAL,
                    batch=batch,
                    processor_func=processor_func
                )
            
            execution_id = self.submit_task(task_id)
            task_ids.append(execution_id)
        
        return task_ids
    
    async def _process_batch_parallel(self, batch: List[Any], processor_func: Callable):
        """並列バッチ処理"""
        tasks = [processor_func(item) for item in batch]
        if tasks and inspect.iscoroutinefunction(processor_func):
            return await asyncio.gather(*tasks)
        else:
            # Use thread pool for non-async functions
            loop = asyncio.get_event_loop()
            futures = [loop.run_in_executor(self.executor, processor_func, item) 
                      for item in batch]
            return await asyncio.gather(*futures)
    
    async def _process_batch_sequential(self, batch: List[Any], processor_func: Callable):
        """順次バッチ処理"""
        results = []
        for item in batch:
            if inspect.iscoroutinefunction(processor_func):
                result = await processor_func(item)
            else:
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(self.executor, processor_func, item)
            results.append(result)
        return results


class ResourceMonitor:
    """リソース監視とスマート配分"""
    
    def __init__(self):
        self.cpu_threshold = 0.8
        self.memory_threshold = 0.8
        self.active_tasks = 0
        
    def can_execute(self, task: AutomationTask) -> bool:
        """タスクが実行可能かチェック"""
        # Simple resource check - can be enhanced with psutil
        return self.active_tasks < 20  # Basic throttling
    
    def acquire_resources(self, task: AutomationTask):
        """リソースを確保"""
        self.active_tasks += 1
    
    def release_resources(self, task: AutomationTask):
        """リソースを解放"""
        self.active_tasks = max(0, self.active_tasks - 1)


class DependencyResolver:
    """依存関係解決エンジン"""
    
    def __init__(self):
        self.dependency_graph = {}
    
    def add_dependency(self, task_id: str, depends_on: List[str]):
        """依存関係を追加"""
        self.dependency_graph[task_id] = depends_on
    
    def get_execution_order(self, task_ids: List[str]) -> List[str]:
        """実行順序を計算（トポロジカルソート）"""
        # Simplified topological sort
        in_degree = {task_id: 0 for task_id in task_ids}
        
        for task_id in task_ids:
            for dep in self.dependency_graph.get(task_id, []):
                if dep in in_degree:
                    in_degree[task_id] += 1
        
        queue = [task_id for task_id, degree in in_degree.items() if degree == 0]
        result = []
        
        while queue:
            current = queue.pop(0)
            result.append(current)
            
            for task_id in task_ids:
                if current in self.dependency_graph.get(task_id, []):
                    in_degree[task_id] -= 1
                    if in_degree[task_id] == 0:
                        queue.append(task_id)
        
        return result


# Global orchestrator instance
_orchestrator: Optional[AutomationOrchestrator] = None


def get_orchestrator() -> AutomationOrchestrator:
    """グローバル・オーケストレーターを取得"""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = AutomationOrchestrator()
        # Don't auto-start during import to avoid event loop issues
        # Will be started when first task is submitted or explicitly started
    return _orchestrator


def automate(task_id: str = None,
            name: str = None,
            priority: Union[TaskPriority, int] = TaskPriority.NORMAL,
            schedule: str = None,
            retry_count: int = 3,
            timeout: float = 300.0,
            dependencies: List[str] = None):
    """デコレーター: 関数を自動化タスクとして登録"""
    def decorator(func: Callable):
        nonlocal task_id, name, priority
        if task_id is None:
            task_id = func.__name__
        if name is None:
            name = func.__doc__ or func.__name__
        
        # Convert integer priority to enum if needed
        if isinstance(priority, int):
            priority_map = {1: TaskPriority.LOW, 2: TaskPriority.NORMAL, 
                          3: TaskPriority.HIGH, 4: TaskPriority.CRITICAL}
            priority = priority_map.get(priority, TaskPriority.NORMAL)
        
        orchestrator = get_orchestrator()
        orchestrator.register_task(
            task_id=task_id,
            func=func,
            name=name,
            priority=priority,
            schedule=schedule,
            retry_count=retry_count,
            timeout=timeout,
            dependencies=dependencies
        )
        
        # Return wrapper that can submit the task
        def wrapper(*args, **kwargs):
            return orchestrator.submit_task(task_id, *args, **kwargs)
        
        wrapper._task_id = task_id
        wrapper._original_func = func
        return wrapper
    
    return decorator


# Built-in automation functions
@automate(task_id="system_health_check", priority=TaskPriority.HIGH)
async def automated_health_check():
    """システムヘルスチェックの自動化"""
    try:
        from blncs.core.health import HealthChecker
        checker = HealthChecker()
        result = await checker.comprehensive_check()
        return result
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise


@automate(task_id="database_maintenance", priority=TaskPriority.NORMAL)
async def automated_database_maintenance():
    """データベースメンテナンスの自動化"""
    try:
        from blncs.core.database import get_database
        db = get_database()
        
        # Vacuum and analyze
        await db.execute("VACUUM")
        await db.execute("ANALYZE")
        
        logger.info("Database maintenance completed")
        return {"status": "success", "timestamp": datetime.now()}
    except Exception as e:
        logger.error(f"Database maintenance failed: {e}")
        raise


@automate(task_id="log_rotation", priority=TaskPriority.LOW)
async def automated_log_rotation():
    """ログローテーションの自動化"""
    try:
        from blncs.core.log_management import LogManager
        log_manager = LogManager()
        rotated_files = await log_manager.rotate_logs()
        
        logger.info(f"Log rotation completed: {len(rotated_files)} files rotated")
        return {"rotated_files": rotated_files}
    except Exception as e:
        logger.error(f"Log rotation failed: {e}")
        raise