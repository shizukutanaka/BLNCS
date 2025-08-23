# BLRCS Async Processing Module
# High-performance asynchronous task processing with concurrency control
import asyncio
import time
import uuid
from typing import Any, Dict, List, Optional, Callable, Awaitable, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import deque
import concurrent.futures
import functools

class TaskStatus(Enum):
    """Task execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class TaskPriority(Enum):
    """Task priority levels"""
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3

@dataclass
class TaskResult:
    """Task execution result"""
    task_id: str
    status: TaskStatus
    result: Any = None
    error: Optional[str] = None
    start_time: float = 0
    end_time: float = 0
    execution_time: float = 0
    retry_count: int = 0

@dataclass
class AsyncTask:
    """Async task definition"""
    task_id: str
    func: Callable[..., Awaitable[Any]]
    args: tuple = field(default_factory=tuple)
    kwargs: dict = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.NORMAL
    max_retries: int = 3
    retry_delay: float = 1.0
    timeout: Optional[float] = None
    created_at: float = field(default_factory=time.time)
    
    def __lt__(self, other):
        """For priority queue ordering"""
        return self.priority.value > other.priority.value

class AsyncProcessor:
    """
    High-performance async task processor with:
    - Priority-based task scheduling
    - Concurrency control
    - Automatic retry with exponential backoff
    - Resource monitoring
    - Batch processing capabilities
    """
    
    def __init__(self, max_workers: int = 10, max_queue_size: int = 1000):
        self.max_workers = max_workers
        self.max_queue_size = max_queue_size
        
        # Task management
        self.task_queue: asyncio.PriorityQueue = asyncio.PriorityQueue(maxsize=max_queue_size)
        self.active_tasks: Dict[str, asyncio.Task] = {}
        self.completed_tasks: Dict[str, TaskResult] = {}
        self.workers: List[asyncio.Task] = []
        
        # Concurrency control
        self.semaphore = asyncio.Semaphore(max_workers)
        self.running = False
        
        # Statistics
        self.stats = {
            "total_submitted": 0,
            "total_completed": 0,
            "total_failed": 0,
            "total_cancelled": 0,
            "avg_execution_time": 0.0,
            "queue_size": 0,
            "active_workers": 0
        }
        
        # Thread pool for CPU-bound tasks
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=min(4, max_workers)
        )
    
    async def start(self):
        """Start the async processor"""
        if self.running:
            return
        
        self.running = True
        
        # Start worker tasks
        for i in range(self.max_workers):
            worker = asyncio.create_task(
                self._worker(f"worker-{i}"),
                name=f"AsyncProcessor-Worker-{i}"
            )
            self.workers.append(worker)
    
    async def stop(self, timeout: float = 5.0):
        """Stop the async processor gracefully"""
        self.running = False
        
        # Cancel all active tasks
        for task in self.active_tasks.values():
            task.cancel()
        
        # Cancel worker tasks
        for worker in self.workers:
            worker.cancel()
        
        # Wait for workers to finish
        if self.workers:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*self.workers, return_exceptions=True),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                pass
        
        # Shutdown thread pool
        self.thread_pool.shutdown(wait=True, timeout=timeout)
        
        self.workers.clear()
        self.active_tasks.clear()
    
    async def submit_async(
        self, 
        func: Callable[..., Awaitable[Any]], 
        *args, 
        priority: TaskPriority = TaskPriority.NORMAL,
        max_retries: int = 3,
        timeout: Optional[float] = None,
        **kwargs
    ) -> str:
        """Submit async task for execution"""
        task_id = str(uuid.uuid4())
        
        task = AsyncTask(
            task_id=task_id,
            func=func,
            args=args,
            kwargs=kwargs,
            priority=priority,
            max_retries=max_retries,
            timeout=timeout
        )
        
        await self.task_queue.put((priority.value, time.time(), task))
        self.stats["total_submitted"] += 1
        self.stats["queue_size"] = self.task_queue.qsize()
        
        return task_id
    
    async def submit_sync(
        self,
        func: Callable[..., Any],
        *args,
        priority: TaskPriority = TaskPriority.NORMAL,
        max_retries: int = 3,
        timeout: Optional[float] = None,
        **kwargs
    ) -> str:
        """Submit sync (CPU-bound) task for execution in thread pool"""
        task_id = str(uuid.uuid4())
        
        # Wrap sync function to run in thread pool
        async def async_wrapper():
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                self.thread_pool,
                functools.partial(func, *args, **kwargs)
            )
        
        task = AsyncTask(
            task_id=task_id,
            func=async_wrapper,
            priority=priority,
            max_retries=max_retries,
            timeout=timeout
        )
        
        await self.task_queue.put((priority.value, time.time(), task))
        self.stats["total_submitted"] += 1
        self.stats["queue_size"] = self.task_queue.qsize()
        
        return task_id
    
    async def submit_batch(
        self,
        tasks: List[Dict[str, Any]],
        batch_size: int = 10,
        priority: TaskPriority = TaskPriority.NORMAL
    ) -> List[str]:
        """Submit multiple tasks as a batch"""
        task_ids = []
        
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            
            # Create batch task
            batch_id = str(uuid.uuid4())
            
            async def batch_processor():
                results = []
                for task_def in batch:
                    try:
                        func = task_def["func"]
                        args = task_def.get("args", ())
                        kwargs = task_def.get("kwargs", {})
                        
                        if asyncio.iscoroutinefunction(func):
                            result = await func(*args, **kwargs)
                        else:
                            loop = asyncio.get_event_loop()
                            result = await loop.run_in_executor(
                                self.thread_pool,
                                functools.partial(func, *args, **kwargs)
                            )
                        results.append({"success": True, "result": result})
                    except Exception as e:
                        results.append({"success": False, "error": str(e)})
                
                return results
            
            task = AsyncTask(
                task_id=batch_id,
                func=batch_processor,
                priority=priority,
                max_retries=1  # Batches get fewer retries
            )
            
            await self.task_queue.put((priority.value, time.time(), task))
            task_ids.append(batch_id)
        
        self.stats["total_submitted"] += len(task_ids)
        self.stats["queue_size"] = self.task_queue.qsize()
        
        return task_ids
    
    async def get_result(self, task_id: str, timeout: Optional[float] = None) -> TaskResult:
        """Get task result (blocks until complete)"""
        start_time = time.time()
        
        while True:
            # Check if completed
            if task_id in self.completed_tasks:
                return self.completed_tasks[task_id]
            
            # Check timeout
            if timeout and (time.time() - start_time) > timeout:
                raise asyncio.TimeoutError(f"Task {task_id} timed out")
            
            # Check if task is still active
            if task_id not in self.active_tasks and task_id not in self.completed_tasks:
                # Task might not have started yet, wait a bit
                await asyncio.sleep(0.1)
                continue
            
            await asyncio.sleep(0.1)
    
    async def get_results(self, task_ids: List[str], timeout: Optional[float] = None) -> List[TaskResult]:
        """Get multiple task results"""
        tasks = [self.get_result(task_id, timeout) for task_id in task_ids]
        return await asyncio.gather(*tasks, return_exceptions=True)
    
    def get_task_status(self, task_id: str) -> TaskStatus:
        """Get current task status"""
        if task_id in self.completed_tasks:
            return self.completed_tasks[task_id].status
        elif task_id in self.active_tasks:
            return TaskStatus.RUNNING
        else:
            return TaskStatus.PENDING
    
    async def cancel_task(self, task_id: str) -> bool:
        """Cancel a task"""
        if task_id in self.active_tasks:
            task = self.active_tasks[task_id]
            task.cancel()
            
            result = TaskResult(
                task_id=task_id,
                status=TaskStatus.CANCELLED,
                end_time=time.time()
            )
            
            self.completed_tasks[task_id] = result
            del self.active_tasks[task_id]
            self.stats["total_cancelled"] += 1
            
            return True
        
        return False
    
    async def _worker(self, worker_name: str):
        """Worker task that processes the queue"""
        while self.running:
            try:
                # Get task from queue
                try:
                    _, _, task = await asyncio.wait_for(
                        self.task_queue.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                self.stats["queue_size"] = self.task_queue.qsize()
                
                # Execute task
                await self._execute_task(task)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Worker {worker_name} error: {e}")
    
    async def _execute_task(self, task: AsyncTask):
        """Execute a single task with retry logic"""
        result = TaskResult(
            task_id=task.task_id,
            status=TaskStatus.RUNNING,
            start_time=time.time()
        )
        
        # Add to active tasks
        async with self.semaphore:
            for attempt in range(task.max_retries + 1):
                try:
                    # Create task
                    if task.timeout:
                        coro = asyncio.wait_for(task.func(*task.args, **task.kwargs), task.timeout)
                    else:
                        coro = task.func(*task.args, **task.kwargs)
                    
                    exec_task = asyncio.create_task(coro)
                    self.active_tasks[task.task_id] = exec_task
                    self.stats["active_workers"] = len(self.active_tasks)
                    
                    # Execute
                    task_result = await exec_task
                    
                    # Success
                    result.status = TaskStatus.COMPLETED
                    result.result = task_result
                    break
                    
                except asyncio.CancelledError:
                    result.status = TaskStatus.CANCELLED
                    break
                
                except Exception as e:
                    result.error = str(e)
                    result.retry_count = attempt
                    
                    if attempt < task.max_retries:
                        # Exponential backoff
                        delay = task.retry_delay * (2 ** attempt)
                        await asyncio.sleep(delay)
                    else:
                        result.status = TaskStatus.FAILED
                        self.stats["total_failed"] += 1
                
                finally:
                    # Remove from active tasks
                    if task.task_id in self.active_tasks:
                        del self.active_tasks[task.task_id]
                        self.stats["active_workers"] = len(self.active_tasks)
        
        # Finalize result
        result.end_time = time.time()
        result.execution_time = result.end_time - result.start_time
        
        if result.status == TaskStatus.COMPLETED:
            self.stats["total_completed"] += 1
        
        # Update average execution time
        total_tasks = self.stats["total_completed"] + self.stats["total_failed"]
        if total_tasks > 0:
            self.stats["avg_execution_time"] = (
                (self.stats["avg_execution_time"] * (total_tasks - 1) + result.execution_time) / total_tasks
            )
        
        # Store result
        self.completed_tasks[task.task_id] = result
        
        # Cleanup old completed tasks (keep last 1000)
        if len(self.completed_tasks) > 1000:
            oldest_tasks = sorted(
                self.completed_tasks.items(),
                key=lambda x: x[1].end_time
            )[:100]
            
            for task_id, _ in oldest_tasks:
                del self.completed_tasks[task_id]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get processor statistics"""
        return {
            **self.stats,
            "queue_size": self.task_queue.qsize(),
            "active_workers": len(self.active_tasks),
            "completed_tasks": len(self.completed_tasks),
            "running": self.running
        }
    
    async def health_check(self) -> bool:
        """Check processor health"""
        return (
            self.running and
            len(self.workers) == self.max_workers and
            self.task_queue.qsize() < self.max_queue_size
        )

# Global async processor instance
_async_processor: Optional[AsyncProcessor] = None

async def get_async_processor(max_workers: int = 10) -> AsyncProcessor:
    """Get global async processor instance"""
    global _async_processor
    
    if _async_processor is None:
        _async_processor = AsyncProcessor(max_workers=max_workers)
        await _async_processor.start()
    
    return _async_processor

async def shutdown_async_processor():
    """Shutdown global async processor"""
    global _async_processor
    
    if _async_processor:
        await _async_processor.stop()
        _async_processor = None