"""
Parallel Processing Optimization System
Optimized concurrent execution with task queuing, thread pooling, and async operations.
"""

import threading
import asyncio
import concurrent.futures
from typing import Dict, Any, List, Optional, Callable, Union, Awaitable
from datetime import datetime, timedelta
from collections import deque, defaultdict
from dataclasses import dataclass, field
import time
import queue
import weakref

from .logger import get_logger
from .config_manager import get_config_manager
from ..utils.performance_profiler import get_profiler


@dataclass
class TaskResult:
    """Result of a parallel task execution"""
    task_id: str
    success: bool
    result: Any = None
    error: Optional[str] = None
    start_time: float = 0
    end_time: float = 0
    duration: float = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class AdaptiveThreadPool:
    """Thread pool that adapts size based on workload"""
    
    def __init__(self, min_workers: int = 2, max_workers: int = 10, 
                 scaling_factor: float = 1.5, idle_timeout: float = 60.0):
        self.min_workers = min_workers
        self.max_workers = max_workers
        self.scaling_factor = scaling_factor
        self.idle_timeout = idle_timeout
        
        self.logger = get_logger(__name__)
        self.profiler = get_profiler()
        
        # Thread pool management
        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="BLNCS_Adaptive"
        )
        
        # Performance tracking
        self.active_tasks = 0
        self.completed_tasks = 0
        self.failed_tasks = 0
        self.task_queue_size = 0
        self.avg_task_duration = 0
        self.task_durations = deque(maxlen=100)
        
        # Adaptive scaling metrics
        self.last_scale_check = time.time()
        self.scale_check_interval = 10.0  # Check every 10 seconds
        
        self._lock = threading.RLock()
        self._shutdown = False
    
    def submit(self, fn: Callable, *args, **kwargs) -> concurrent.futures.Future:
        """Submit task to thread pool"""
        if self._shutdown:
            raise RuntimeError("Thread pool is shut down")
        
        start_time = time.time()
        
        def wrapped_fn(*args, **kwargs):
            task_start = time.time()
            try:
                with self._lock:
                    self.active_tasks += 1
                
                result = fn(*args, **kwargs)
                
                # Track performance
                duration = time.time() - task_start
                with self._lock:
                    self.completed_tasks += 1
                    self.task_durations.append(duration)
                    if self.task_durations:
                        self.avg_task_duration = sum(self.task_durations) / len(self.task_durations)
                
                return result
                
            except Exception as e:
                with self._lock:
                    self.failed_tasks += 1
                raise
            finally:
                with self._lock:
                    self.active_tasks -= 1
                    self._check_scaling()
        
        future = self.executor.submit(wrapped_fn, *args, **kwargs)
        
        with self._lock:
            self.task_queue_size = getattr(self.executor._work_queue, 'qsize', lambda: 0)()
        
        return future
    
    def _check_scaling(self):
        """Check if thread pool should be scaled"""
        current_time = time.time()
        if current_time - self.last_scale_check < self.scale_check_interval:
            return
        
        self.last_scale_check = current_time
        
        # Simple scaling logic based on queue size and task duration
        current_threads = self.executor._threads
        queue_size = self.task_queue_size
        
        if queue_size > len(current_threads) * 2 and len(current_threads) < self.max_workers:
            # Scale up if queue is backing up
            self.logger.debug(f"Considering thread pool scale up: queue={queue_size}, threads={len(current_threads)}")
        elif queue_size == 0 and len(current_threads) > self.min_workers:
            # Scale down if no queue and above minimum
            self.logger.debug(f"Considering thread pool scale down: queue={queue_size}, threads={len(current_threads)}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get thread pool statistics"""
        with self._lock:
            current_threads = len(self.executor._threads) if hasattr(self.executor, '_threads') else 0
            
            return {
                'active_tasks': self.active_tasks,
                'completed_tasks': self.completed_tasks,
                'failed_tasks': self.failed_tasks,
                'current_threads': current_threads,
                'max_workers': self.max_workers,
                'queue_size': self.task_queue_size,
                'avg_task_duration': self.avg_task_duration,
                'success_rate': self.completed_tasks / (self.completed_tasks + self.failed_tasks) if (self.completed_tasks + self.failed_tasks) > 0 else 1.0
            }
    
    def shutdown(self, wait: bool = True):
        """Shutdown thread pool"""
        self._shutdown = True
        self.executor.shutdown(wait=wait)


class TaskQueue:
    """Priority task queue with batching support"""
    
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self.queue = queue.PriorityQueue(max_size)
        self.task_counter = 0
        self.completed_tasks = {}
        self.failed_tasks = {}
        
        self._lock = threading.RLock()
        self.logger = get_logger(__name__)
    
    def add_task(self, task_fn: Callable, priority: int = 5, task_id: Optional[str] = None,
                metadata: Dict[str, Any] = None) -> str:
        """Add task to queue with priority (lower number = higher priority)"""
        if task_id is None:
            with self._lock:
                self.task_counter += 1
                task_id = f"task_{self.task_counter}"
        
        task_item = {
            'id': task_id,
            'function': task_fn,
            'priority': priority,
            'created_at': time.time(),
            'metadata': metadata or {}
        }
        
        try:
            # Use negative priority for correct ordering (lower number = higher priority)
            self.queue.put((-priority, task_id, task_item), timeout=1.0)
            return task_id
        except queue.Full:
            self.logger.warning(f"Task queue full, dropping task {task_id}")
            raise
    
    def get_task(self, timeout: float = 1.0) -> Optional[Dict[str, Any]]:
        """Get next task from queue"""
        try:
            _, task_id, task_item = self.queue.get(timeout=timeout)
            return task_item
        except queue.Empty:
            return None
    
    def mark_completed(self, task_id: str, result: Any):
        """Mark task as completed"""
        with self._lock:
            self.completed_tasks[task_id] = {
                'result': result,
                'completed_at': time.time()
            }
    
    def mark_failed(self, task_id: str, error: str):
        """Mark task as failed"""
        with self._lock:
            self.failed_tasks[task_id] = {
                'error': error,
                'failed_at': time.time()
            }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get queue statistics"""
        with self._lock:
            return {
                'queue_size': self.queue.qsize(),
                'max_size': self.max_size,
                'completed_tasks': len(self.completed_tasks),
                'failed_tasks': len(self.failed_tasks),
                'utilization': self.queue.qsize() / self.max_size
            }


class ParallelExecutor:
    """High-level parallel execution coordinator"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config_manager = get_config_manager()
        self.profiler = get_profiler()
        
        # Configuration
        self.max_workers = self.config_manager.get('parallel.max_workers', 8)
        self.enable_batching = self.config_manager.get('parallel.enable_batching', True)
        self.batch_size = self.config_manager.get('parallel.batch_size', 10)
        self.batch_timeout = self.config_manager.get('parallel.batch_timeout', 2.0)
        
        # Thread pools
        self.io_pool = AdaptiveThreadPool(
            min_workers=2,
            max_workers=self.max_workers,
            scaling_factor=1.5
        )
        
        self.cpu_pool = AdaptiveThreadPool(
            min_workers=1,
            max_workers=max(2, self.max_workers // 2),
            scaling_factor=1.2
        )
        
        # Task management
        self.task_queue = TaskQueue(max_size=self.config_manager.get('parallel.queue_size', 1000))
        self.batch_processor = None
        self.running_tasks = weakref.WeakValueDictionary()
        
        # Performance tracking
        self.execution_stats = {
            'total_tasks': 0,
            'parallel_tasks': 0,
            'batched_tasks': 0,
            'avg_speedup': 1.0,
            'peak_concurrent_tasks': 0
        }
        
        self._start_batch_processor()
    
    def _start_batch_processor(self):
        """Start batch processing thread"""
        if self.enable_batching:
            self.batch_processor = threading.Thread(target=self._batch_processing_loop, daemon=True)
            self.batch_processor.start()
    
    def _batch_processing_loop(self):
        """Process tasks in batches when beneficial"""
        batch = []
        last_batch_time = time.time()
        
        while True:
            try:
                task = self.task_queue.get_task(timeout=0.5)
                if task:
                    batch.append(task)
                
                # Process batch if it's full or timeout reached
                current_time = time.time()
                should_process = (
                    len(batch) >= self.batch_size or
                    (batch and (current_time - last_batch_time) >= self.batch_timeout)
                )
                
                if should_process and batch:
                    self._process_batch(batch)
                    batch.clear()
                    last_batch_time = current_time
                
            except Exception as e:
                self.logger.error(f"Batch processing error: {e}")
                time.sleep(1)
    
    def _process_batch(self, batch: List[Dict[str, Any]]):
        """Process a batch of tasks"""
        if len(batch) == 1:
            # Single task, execute directly
            task = batch[0]
            future = self._execute_single_task(task)
            return
        
        # Multiple tasks, execute in parallel
        futures = []
        for task in batch:
            future = self._execute_single_task(task, is_batched=True)
            futures.append((task['id'], future))
        
        # Wait for batch completion
        for task_id, future in futures:
            try:
                result = future.result(timeout=30)  # 30 second timeout
                self.task_queue.mark_completed(task_id, result)
            except Exception as e:
                self.task_queue.mark_failed(task_id, str(e))
        
        self.execution_stats['batched_tasks'] += len(batch)
    
    def _execute_single_task(self, task: Dict[str, Any], is_batched: bool = False) -> concurrent.futures.Future:
        """Execute a single task"""
        task_id = task['id']
        task_fn = task['function']
        metadata = task.get('metadata', {})
        
        # Choose appropriate thread pool based on task type
        is_io_bound = metadata.get('io_bound', True)
        pool = self.io_pool if is_io_bound else self.cpu_pool
        
        # Execute task
        future = pool.submit(task_fn)
        self.running_tasks[task_id] = future
        
        if not is_batched:
            self.execution_stats['total_tasks'] += 1
        
        return future
    
    def execute_parallel(self, tasks: List[Callable], io_bound: bool = True, 
                        max_workers: Optional[int] = None) -> List[TaskResult]:
        """Execute multiple tasks in parallel"""
        if not tasks:
            return []
        
        start_time = time.time()
        max_workers = max_workers or min(len(tasks), self.max_workers)
        
        # Choose thread pool
        pool = self.io_pool if io_bound else self.cpu_pool
        
        # Submit all tasks
        futures = {}
        for i, task in enumerate(tasks):
            task_id = f"parallel_{start_time}_{i}"
            future = pool.submit(task)
            futures[task_id] = future
        
        # Collect results
        results = []
        for task_id, future in futures.items():
            task_start = time.time()
            try:
                result = future.result(timeout=60)  # 60 second timeout
                task_end = time.time()
                
                results.append(TaskResult(
                    task_id=task_id,
                    success=True,
                    result=result,
                    start_time=task_start,
                    end_time=task_end,
                    duration=(task_end - task_start) * 1000,  # milliseconds
                    metadata={'io_bound': io_bound}
                ))
                
            except Exception as e:
                task_end = time.time()
                results.append(TaskResult(
                    task_id=task_id,
                    success=False,
                    error=str(e),
                    start_time=task_start,
                    end_time=task_end,
                    duration=(task_end - task_start) * 1000,
                    metadata={'io_bound': io_bound}
                ))
        
        # Update statistics
        total_time = time.time() - start_time
        sequential_estimate = sum(r.duration for r in results) / 1000  # Convert to seconds
        speedup = sequential_estimate / total_time if total_time > 0 else 1.0
        
        self.execution_stats['parallel_tasks'] += len(tasks)
        self.execution_stats['avg_speedup'] = (
            (self.execution_stats['avg_speedup'] * self.execution_stats['total_tasks'] + speedup * len(tasks)) /
            (self.execution_stats['total_tasks'] + len(tasks))
        )
        self.execution_stats['total_tasks'] += len(tasks)
        
        current_concurrent = len([f for f in futures.values() if not f.done()])
        self.execution_stats['peak_concurrent_tasks'] = max(
            self.execution_stats['peak_concurrent_tasks'],
            current_concurrent
        )
        
        return results
    
    def execute_with_retry(self, task: Callable, max_retries: int = 3, 
                          retry_delay: float = 1.0, backoff_multiplier: float = 2.0) -> TaskResult:
        """Execute task with retry logic"""
        task_id = f"retry_{time.time()}"
        
        for attempt in range(max_retries + 1):
            start_time = time.time()
            
            try:
                result = task()
                end_time = time.time()
                
                return TaskResult(
                    task_id=task_id,
                    success=True,
                    result=result,
                    start_time=start_time,
                    end_time=end_time,
                    duration=(end_time - start_time) * 1000,
                    metadata={'attempts': attempt + 1}
                )
                
            except Exception as e:
                end_time = time.time()
                
                if attempt < max_retries:
                    self.logger.warning(f"Task {task_id} failed (attempt {attempt + 1}), retrying in {retry_delay}s: {e}")
                    time.sleep(retry_delay)
                    retry_delay *= backoff_multiplier
                else:
                    return TaskResult(
                        task_id=task_id,
                        success=False,
                        error=str(e),
                        start_time=start_time,
                        end_time=end_time,
                        duration=(end_time - start_time) * 1000,
                        metadata={'attempts': attempt + 1}
                    )
        
        return TaskResult(task_id=task_id, success=False, error="Max retries exceeded")
    
    async def execute_async_batch(self, tasks: List[Callable[[], Awaitable[Any]]]) -> List[TaskResult]:
        """Execute async tasks in batch"""
        if not tasks:
            return []
        
        start_time = time.time()
        results = []
        
        # Create async tasks
        async_tasks = []
        for i, task in enumerate(tasks):
            task_id = f"async_batch_{start_time}_{i}"
            async_tasks.append((task_id, task()))
        
        # Execute all tasks concurrently
        for task_id, coro in async_tasks:
            task_start = time.time()
            try:
                result = await coro
                task_end = time.time()
                
                results.append(TaskResult(
                    task_id=task_id,
                    success=True,
                    result=result,
                    start_time=task_start,
                    end_time=task_end,
                    duration=(task_end - task_start) * 1000,
                    metadata={'async': True}
                ))
                
            except Exception as e:
                task_end = time.time()
                results.append(TaskResult(
                    task_id=task_id,
                    success=False,
                    error=str(e),
                    start_time=task_start,
                    end_time=task_end,
                    duration=(task_end - task_start) * 1000,
                    metadata={'async': True}
                ))
        
        return results
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get parallel execution performance statistics"""
        io_stats = self.io_pool.get_stats()
        cpu_stats = self.cpu_pool.get_stats()
        queue_stats = self.task_queue.get_stats()
        
        return {
            'execution_stats': self.execution_stats,
            'io_pool': io_stats,
            'cpu_pool': cpu_stats,
            'task_queue': queue_stats,
            'running_tasks': len(self.running_tasks),
            'batch_processing_enabled': self.enable_batching,
            'configuration': {
                'max_workers': self.max_workers,
                'batch_size': self.batch_size,
                'batch_timeout': self.batch_timeout
            }
        }
    
    def optimize_concurrency(self) -> Dict[str, Any]:
        """Optimize concurrency settings based on performance data"""
        io_stats = self.io_pool.get_stats()
        cpu_stats = self.cpu_pool.get_stats()
        
        optimizations = {}
        
        # Optimize IO pool
        if io_stats['queue_size'] > io_stats['current_threads'] * 3:
            # High queue, consider increasing threads
            new_max = min(self.max_workers * 2, 20)
            optimizations['io_pool_scaling'] = f"Consider increasing IO pool to {new_max} workers"
        
        # Optimize CPU pool
        if cpu_stats['avg_task_duration'] > 1000 and cpu_stats['current_threads'] < 4:
            # Long CPU tasks, might benefit from more threads
            optimizations['cpu_pool_scaling'] = "Consider increasing CPU pool for long-running tasks"
        
        # Optimize batching
        if self.execution_stats['batched_tasks'] > 0:
            batch_efficiency = self.execution_stats['batched_tasks'] / self.execution_stats['total_tasks']
            if batch_efficiency < 0.1:  # Less than 10% batched
                optimizations['batching'] = "Low batch utilization, consider reducing batch size or timeout"
        
        return {
            'optimizations_suggested': optimizations,
            'current_performance': {
                'avg_speedup': self.execution_stats['avg_speedup'],
                'peak_concurrent': self.execution_stats['peak_concurrent_tasks'],
                'batch_efficiency': self.execution_stats['batched_tasks'] / max(self.execution_stats['total_tasks'], 1)
            }
        }
    
    def shutdown(self):
        """Shutdown parallel executor"""
        self.io_pool.shutdown()
        self.cpu_pool.shutdown()
        
        if self.batch_processor and self.batch_processor.is_alive():
            # Stop batch processor (it's a daemon thread, so it will stop when main exits)
            pass


# Global parallel executor instance
_parallel_executor = None

def get_parallel_executor() -> ParallelExecutor:
    """Get or create global parallel executor instance"""
    global _parallel_executor
    if _parallel_executor is None:
        _parallel_executor = ParallelExecutor()
    return _parallel_executor


def parallel_map(func: Callable, items: List[Any], max_workers: Optional[int] = None, 
                io_bound: bool = True) -> List[TaskResult]:
    """Execute function on list of items in parallel"""
    if not items:
        return []
    
    executor = get_parallel_executor()
    tasks = [lambda item=item: func(item) for item in items]
    return executor.execute_parallel(tasks, io_bound=io_bound, max_workers=max_workers)


def run_parallel(*functions: Callable) -> List[TaskResult]:
    """Run multiple functions in parallel"""
    if not functions:
        return []
    
    executor = get_parallel_executor()
    return executor.execute_parallel(list(functions))


# Decorator for automatic parallelization
def parallelize(io_bound: bool = True, max_retries: int = 0):
    """Decorator to automatically parallelize function execution"""
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            executor = get_parallel_executor()
            task = lambda: func(*args, **kwargs)
            
            if max_retries > 0:
                return executor.execute_with_retry(task, max_retries=max_retries)
            else:
                results = executor.execute_parallel([task], io_bound=io_bound)
                return results[0] if results else None
        
        return wrapper
    return decorator