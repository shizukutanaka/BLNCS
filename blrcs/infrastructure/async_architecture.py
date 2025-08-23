# BLRCS Advanced Async Architecture
# High-performance async system following Carmack's optimization philosophy
import asyncio
import threading
import multiprocessing
import time
import weakref
import gc
from datetime import datetime, timedelta
from typing import (
    Dict, List, Any, Optional, Callable, Awaitable, Union, 
    TypeVar, Generic, Protocol, runtime_checkable
)
from dataclasses import dataclass, field
from enum import Enum
from collections import deque, defaultdict
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import queue
import uvloop
import signal
import psutil
import sys

T = TypeVar('T')
R = TypeVar('R')

class TaskPriority(Enum):
    """Task priority levels"""
    CRITICAL = 0    # System critical operations
    HIGH = 1        # User-facing operations
    NORMAL = 2      # Background processing
    LOW = 3         # Maintenance tasks
    IDLE = 4        # Cleanup operations

class WorkerType(Enum):
    """Worker types for different workloads"""
    CPU_BOUND = "cpu_bound"
    IO_BOUND = "io_bound"
    MEMORY_BOUND = "memory_bound"
    NETWORK_BOUND = "network_bound"

@runtime_checkable
class AsyncTaskProtocol(Protocol):
    """Protocol for async tasks"""
    async def execute(self) -> Any:
        """Execute the task"""
        ...
    
    def get_priority(self) -> TaskPriority:
        """Get task priority"""
        ...
    
    def get_timeout(self) -> Optional[float]:
        """Get task timeout in seconds"""
        ...

@dataclass
class TaskMetrics:
    """Task execution metrics"""
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    execution_time: Optional[float] = None
    memory_usage: Optional[int] = None
    cpu_usage: Optional[float] = None
    result_size: Optional[int] = None
    error: Optional[str] = None
    retry_count: int = 0

@dataclass
class AsyncTask(Generic[T]):
    """High-performance async task wrapper"""
    id: str
    coro: Awaitable[T]
    priority: TaskPriority = TaskPriority.NORMAL
    timeout: Optional[float] = None
    max_retries: int = 3
    retry_delay: float = 1.0
    worker_type: WorkerType = WorkerType.IO_BOUND
    metadata: Dict[str, Any] = field(default_factory=dict)
    metrics: TaskMetrics = field(default_factory=TaskMetrics)
    dependencies: List[str] = field(default_factory=list)
    callback: Optional[Callable[[Any], None]] = None
    error_callback: Optional[Callable[[Exception], None]] = None
    
    def __post_init__(self):
        """Initialize task state"""
        self._future: Optional[asyncio.Future] = None
        self._cancelled = False
        self._result: Optional[T] = None
        self._exception: Optional[Exception] = None
    
    async def execute(self) -> T:
        """Execute the task with metrics collection"""
        start_time = time.perf_counter()
        start_memory = psutil.Process().memory_info().rss
        
        self.metrics.started_at = datetime.now()
        
        try:
            if self.timeout:
                result = await asyncio.wait_for(self.coro, timeout=self.timeout)
            else:
                result = await self.coro
            
            self._result = result
            
            # Call success callback
            if self.callback:
                try:
                    self.callback(result)
                except Exception:
                    pass  # Don't let callback errors affect task
            
            return result
            
        except Exception as e:
            self._exception = e
            self.metrics.error = str(e)
            
            # Call error callback
            if self.error_callback:
                try:
                    self.error_callback(e)
                except Exception:
                    pass
            
            raise
            
        finally:
            end_time = time.perf_counter()
            end_memory = psutil.Process().memory_info().rss
            
            self.metrics.completed_at = datetime.now()
            self.metrics.execution_time = end_time - start_time
            self.metrics.memory_usage = end_memory - start_memory
            
            # Estimate result size
            if self._result is not None:
                try:
                    self.metrics.result_size = sys.getsizeof(self._result)
                except:
                    pass
    
    def cancel(self):
        """Cancel the task"""
        self._cancelled = True
        if self._future and not self._future.done():
            self._future.cancel()
    
    def is_cancelled(self) -> bool:
        """Check if task is cancelled"""
        return self._cancelled
    
    def is_done(self) -> bool:
        """Check if task is completed"""
        return self._future is not None and self._future.done()
    
    def get_result(self) -> Optional[T]:
        """Get task result if completed"""
        return self._result
    
    def get_exception(self) -> Optional[Exception]:
        """Get task exception if failed"""
        return self._exception

class TaskQueue:
    """Priority-based task queue with batching"""
    
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.queues: Dict[TaskPriority, deque] = {
            priority: deque() for priority in TaskPriority
        }
        self.task_map: Dict[str, AsyncTask] = {}
        self.lock = asyncio.Lock()
        self.not_empty = asyncio.Condition(self.lock)
        self.size = 0
        
        # Batch processing configuration
        self.batch_size = 100
        self.batch_timeout = 0.1  # 100ms
    
    async def put(self, task: AsyncTask) -> bool:
        """Add task to queue"""
        async with self.lock:
            if self.size >= self.max_size:
                return False
            
            self.queues[task.priority].append(task)
            self.task_map[task.id] = task
            self.size += 1
            
            async with self.not_empty:
                self.not_empty.notify()
            
            return True
    
    async def get(self, timeout: Optional[float] = None) -> Optional[AsyncTask]:
        """Get highest priority task"""
        async with self.not_empty:
            while self.size == 0:
                try:
                    await asyncio.wait_for(self.not_empty.wait(), timeout=timeout)
                except asyncio.TimeoutError:
                    return None
            
            # Get highest priority task
            for priority in TaskPriority:
                if self.queues[priority]:
                    task = self.queues[priority].popleft()
                    del self.task_map[task.id]
                    self.size -= 1
                    return task
            
            return None
    
    async def get_batch(self, max_batch_size: Optional[int] = None) -> List[AsyncTask]:
        """Get batch of tasks for processing"""
        if max_batch_size is None:
            max_batch_size = self.batch_size
        
        batch = []
        
        async with self.lock:
            # Collect tasks by priority
            for priority in TaskPriority:
                while self.queues[priority] and len(batch) < max_batch_size:
                    task = self.queues[priority].popleft()
                    del self.task_map[task.id]
                    self.size -= 1
                    batch.append(task)
                
                if len(batch) >= max_batch_size:
                    break
        
        return batch
    
    async def remove(self, task_id: str) -> bool:
        """Remove task from queue"""
        async with self.lock:
            if task_id not in self.task_map:
                return False
            
            task = self.task_map[task_id]
            
            # Find and remove from appropriate queue
            try:
                self.queues[task.priority].remove(task)
                del self.task_map[task_id]
                self.size -= 1
                return True
            except ValueError:
                return False
    
    def qsize(self) -> int:
        """Get queue size"""
        return self.size
    
    def get_stats(self) -> Dict[str, int]:
        """Get queue statistics"""
        return {
            'total': self.size,
            **{f'{priority.name.lower()}': len(self.queues[priority]) 
               for priority in TaskPriority}
        }

class WorkerPool:
    """High-performance worker pool with load balancing"""
    
    def __init__(self, 
                 worker_count: int = None,
                 worker_type: WorkerType = WorkerType.IO_BOUND,
                 max_tasks_per_worker: int = 1000):
        
        if worker_count is None:
            if worker_type == WorkerType.CPU_BOUND:
                worker_count = multiprocessing.cpu_count()
            else:
                worker_count = min(32, (multiprocessing.cpu_count() or 1) * 4)
        
        self.worker_count = worker_count
        self.worker_type = worker_type
        self.max_tasks_per_worker = max_tasks_per_worker
        
        # Worker management
        self.workers: List[asyncio.Task] = []
        self.worker_stats: List[Dict[str, Any]] = []
        self.task_queue = TaskQueue()
        self.running = False
        
        # Load balancing
        self.worker_loads: List[int] = [0] * worker_count
        self.round_robin_counter = 0
        
        # Performance tracking
        self.total_tasks_processed = 0
        self.total_execution_time = 0.0
        self.peak_memory_usage = 0
    
    async def start(self):
        """Start worker pool"""
        if self.running:
            return
        
        self.running = True
        
        # Initialize worker stats
        self.worker_stats = [
            {
                'id': i,
                'tasks_processed': 0,
                'total_time': 0.0,
                'current_load': 0,
                'last_activity': datetime.now()
            }
            for i in range(self.worker_count)
        ]
        
        # Start workers
        for i in range(self.worker_count):
            worker = asyncio.create_task(self._worker_loop(i))
            self.workers.append(worker)
    
    async def stop(self, timeout: float = 30.0):
        """Stop worker pool gracefully"""
        self.running = False
        
        # Cancel all workers
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
                pass  # Force shutdown
        
        self.workers.clear()
    
    async def submit_task(self, task: AsyncTask) -> bool:
        """Submit task to worker pool"""
        return await self.task_queue.put(task)
    
    async def _worker_loop(self, worker_id: int):
        """Main worker loop"""
        worker_stats = self.worker_stats[worker_id]
        
        while self.running:
            try:
                # Get task batch for better performance
                if self.worker_type == WorkerType.CPU_BOUND:
                    # CPU-bound tasks: process one at a time
                    batch = [await self.task_queue.get(timeout=1.0)]
                    if batch[0] is None:
                        continue
                else:
                    # IO-bound tasks: process in batches
                    batch = await self.task_queue.get_batch()
                    if not batch:
                        await asyncio.sleep(0.01)  # Small delay to prevent busy waiting
                        continue
                
                # Process batch
                await self._process_batch(worker_id, batch)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                # Log error but continue working
                print(f"Worker {worker_id} error: {e}")
                await asyncio.sleep(0.1)
        
        # Worker shutdown
        worker_stats['last_activity'] = datetime.now()
    
    async def _process_batch(self, worker_id: int, batch: List[AsyncTask]):
        """Process a batch of tasks"""
        worker_stats = self.worker_stats[worker_id]
        
        for task in batch:
            if not self.running or task.is_cancelled():
                continue
            
            start_time = time.perf_counter()
            
            try:
                # Update worker load
                self.worker_loads[worker_id] += 1
                worker_stats['current_load'] += 1
                
                # Execute task with retries
                await self._execute_with_retry(task)
                
                # Update statistics
                execution_time = time.perf_counter() - start_time
                worker_stats['tasks_processed'] += 1
                worker_stats['total_time'] += execution_time
                worker_stats['last_activity'] = datetime.now()
                
                self.total_tasks_processed += 1
                self.total_execution_time += execution_time
                
            except Exception as e:
                # Task failed after retries
                task.metrics.error = str(e)
                if task.error_callback:
                    try:
                        task.error_callback(e)
                    except:
                        pass
            
            finally:
                # Update worker load
                self.worker_loads[worker_id] -= 1
                worker_stats['current_load'] -= 1
    
    async def _execute_with_retry(self, task: AsyncTask):
        """Execute task with retry logic"""
        for attempt in range(task.max_retries + 1):
            try:
                task.metrics.retry_count = attempt
                result = await task.execute()
                return result
                
            except Exception as e:
                if attempt < task.max_retries:
                    # Wait before retry with exponential backoff
                    delay = task.retry_delay * (2 ** attempt)
                    await asyncio.sleep(delay)
                    continue
                else:
                    # Final attempt failed
                    raise e
    
    def get_stats(self) -> Dict[str, Any]:
        """Get worker pool statistics"""
        active_workers = sum(1 for load in self.worker_loads if load > 0)
        avg_execution_time = (
            self.total_execution_time / self.total_tasks_processed
            if self.total_tasks_processed > 0 else 0.0
        )
        
        return {
            'worker_count': self.worker_count,
            'worker_type': self.worker_type.value,
            'active_workers': active_workers,
            'total_tasks_processed': self.total_tasks_processed,
            'avg_execution_time': avg_execution_time,
            'queue_size': self.task_queue.qsize(),
            'queue_stats': self.task_queue.get_stats(),
            'worker_loads': self.worker_loads.copy(),
            'peak_memory_usage': self.peak_memory_usage
        }

class AsyncScheduler:
    """Advanced task scheduler with dependency management"""
    
    def __init__(self):
        self.scheduled_tasks: Dict[str, AsyncTask] = {}
        self.dependency_graph: Dict[str, Set[str]] = defaultdict(set)
        self.completed_tasks: Set[str] = set()
        self.failed_tasks: Set[str] = set()
        self.lock = asyncio.Lock()
        
        # Scheduling parameters
        self.check_interval = 0.1  # 100ms
        self.max_concurrent_tasks = 1000
        self.running = False
        self.scheduler_task: Optional[asyncio.Task] = None
    
    async def start(self):
        """Start the scheduler"""
        if self.running:
            return
        
        self.running = True
        self.scheduler_task = asyncio.create_task(self._scheduler_loop())
    
    async def stop(self):
        """Stop the scheduler"""
        self.running = False
        if self.scheduler_task:
            self.scheduler_task.cancel()
            try:
                await self.scheduler_task
            except asyncio.CancelledError:
                pass
    
    async def schedule_task(self, task: AsyncTask, dependencies: List[str] = None):
        """Schedule a task with optional dependencies"""
        async with self.lock:
            self.scheduled_tasks[task.id] = task
            
            if dependencies:
                task.dependencies = dependencies
                for dep_id in dependencies:
                    self.dependency_graph[dep_id].add(task.id)
    
    async def _scheduler_loop(self):
        """Main scheduler loop"""
        while self.running:
            try:
                ready_tasks = await self._get_ready_tasks()
                
                for task in ready_tasks:
                    # Execute task asynchronously
                    asyncio.create_task(self._execute_scheduled_task(task))
                
                await asyncio.sleep(self.check_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Scheduler error: {e}")
                await asyncio.sleep(1.0)
    
    async def _get_ready_tasks(self) -> List[AsyncTask]:
        """Get tasks that are ready to execute"""
        ready_tasks = []
        
        async with self.lock:
            for task_id, task in list(self.scheduled_tasks.items()):
                # Check if all dependencies are completed
                if all(dep_id in self.completed_tasks 
                       for dep_id in task.dependencies):
                    ready_tasks.append(task)
                    del self.scheduled_tasks[task_id]
        
        return ready_tasks
    
    async def _execute_scheduled_task(self, task: AsyncTask):
        """Execute a scheduled task"""
        try:
            await task.execute()
            
            async with self.lock:
                self.completed_tasks.add(task.id)
                
                # Notify dependent tasks
                for dependent_id in self.dependency_graph[task.id]:
                    # Dependent tasks will be picked up by scheduler loop
                    pass
                
                del self.dependency_graph[task.id]
            
        except Exception as e:
            async with self.lock:
                self.failed_tasks.add(task.id)
                
                # Mark dependent tasks as failed too
                await self._mark_dependents_failed(task.id)
    
    async def _mark_dependents_failed(self, failed_task_id: str):
        """Mark all dependent tasks as failed"""
        dependents = self.dependency_graph[failed_task_id].copy()
        
        for dependent_id in dependents:
            if dependent_id in self.scheduled_tasks:
                self.failed_tasks.add(dependent_id)
                del self.scheduled_tasks[dependent_id]
                
                # Recursively mark their dependents as failed
                await self._mark_dependents_failed(dependent_id)

class AsyncArchitecture:
    """Main async architecture coordinator"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Core components
        self.io_worker_pool: Optional[WorkerPool] = None
        self.cpu_worker_pool: Optional[WorkerPool] = None
        self.scheduler: Optional[AsyncScheduler] = None
        
        # Event loop optimization
        self.use_uvloop = self.config.get('use_uvloop', True)
        
        # Performance monitoring
        self.metrics = {
            'start_time': None,
            'tasks_submitted': 0,
            'tasks_completed': 0,
            'tasks_failed': 0,
            'avg_latency': 0.0,
            'peak_memory': 0,
            'cpu_usage': 0.0
        }
        
        # Shutdown management
        self.shutdown_event = asyncio.Event()
        self.cleanup_tasks: List[Callable] = []
        
        # Signal handlers
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        """Setup graceful shutdown signal handlers"""
        def signal_handler(signum, frame):
            print(f"Received signal {signum}, initiating graceful shutdown...")
            asyncio.create_task(self.shutdown())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    async def initialize(self):
        """Initialize the async architecture"""
        # Set up event loop
        if self.use_uvloop and sys.platform != 'win32':
            try:
                import uvloop
                uvloop.install()
                print("Using uvloop for better performance")
            except ImportError:
                print("uvloop not available, using default event loop")
        
        # Configure worker pools
        io_workers = self.config.get('io_workers', min(32, multiprocessing.cpu_count() * 4))
        cpu_workers = self.config.get('cpu_workers', multiprocessing.cpu_count())
        
        self.io_worker_pool = WorkerPool(
            worker_count=io_workers,
            worker_type=WorkerType.IO_BOUND
        )
        
        self.cpu_worker_pool = WorkerPool(
            worker_count=cpu_workers,
            worker_type=WorkerType.CPU_BOUND
        )
        
        self.scheduler = AsyncScheduler()
        
        # Start components
        await self.io_worker_pool.start()
        await self.cpu_worker_pool.start()
        await self.scheduler.start()
        
        self.metrics['start_time'] = datetime.now()
        print(f"Async architecture initialized: {io_workers} IO workers, {cpu_workers} CPU workers")
    
    async def submit_task(self, 
                         coro: Awaitable[T],
                         priority: TaskPriority = TaskPriority.NORMAL,
                         worker_type: WorkerType = WorkerType.IO_BOUND,
                         timeout: Optional[float] = None,
                         dependencies: List[str] = None,
                         **kwargs) -> AsyncTask[T]:
        """Submit a task for execution"""
        
        task_id = f"task_{int(time.time() * 1000000)}"
        
        task = AsyncTask(
            id=task_id,
            coro=coro,
            priority=priority,
            timeout=timeout,
            worker_type=worker_type,
            dependencies=dependencies or [],
            **kwargs
        )
        
        self.metrics['tasks_submitted'] += 1
        
        if dependencies:
            # Use scheduler for dependent tasks
            await self.scheduler.schedule_task(task, dependencies)
        else:
            # Submit directly to appropriate worker pool
            if worker_type == WorkerType.CPU_BOUND:
                await self.cpu_worker_pool.submit_task(task)
            else:
                await self.io_worker_pool.submit_task(task)
        
        return task
    
    async def create_task_group(self, 
                               tasks: List[Awaitable],
                               priority: TaskPriority = TaskPriority.NORMAL,
                               worker_type: WorkerType = WorkerType.IO_BOUND) -> List[AsyncTask]:
        """Create a group of related tasks"""
        task_group = []
        
        for i, coro in enumerate(tasks):
            task = await self.submit_task(
                coro=coro,
                priority=priority,
                worker_type=worker_type,
                metadata={'group_id': f'group_{int(time.time())}', 'group_index': i}
            )
            task_group.append(task)
        
        return task_group
    
    async def wait_for_completion(self, 
                                 tasks: List[AsyncTask],
                                 timeout: Optional[float] = None,
                                 return_when: str = 'ALL_COMPLETED') -> tuple[List[AsyncTask], List[AsyncTask]]:
        """Wait for task completion"""
        futures = [task._future for task in tasks if task._future]
        
        if not futures:
            return [], tasks
        
        try:
            done, pending = await asyncio.wait(
                futures,
                timeout=timeout,
                return_when=getattr(asyncio, return_when)
            )
            
            done_tasks = [task for task in tasks if task._future in done]
            pending_tasks = [task for task in tasks if task._future in pending]
            
            return done_tasks, pending_tasks
            
        except asyncio.TimeoutError:
            return [], tasks
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive performance metrics"""
        uptime = (
            (datetime.now() - self.metrics['start_time']).total_seconds()
            if self.metrics['start_time'] else 0
        )
        
        # Collect worker pool stats
        io_stats = self.io_worker_pool.get_stats() if self.io_worker_pool else {}
        cpu_stats = self.cpu_worker_pool.get_stats() if self.cpu_worker_pool else {}
        
        # System metrics
        process = psutil.Process()
        memory_info = process.memory_info()
        cpu_percent = process.cpu_percent()
        
        return {
            'uptime_seconds': uptime,
            'system': {
                'memory_rss': memory_info.rss,
                'memory_vms': memory_info.vms,
                'cpu_percent': cpu_percent,
                'thread_count': threading.active_count(),
                'gc_stats': {
                    'collections': gc.get_stats(),
                    'objects': len(gc.get_objects())
                }
            },
            'tasks': {
                'submitted': self.metrics['tasks_submitted'],
                'completed': self.metrics['tasks_completed'],
                'failed': self.metrics['tasks_failed'],
                'success_rate': (
                    self.metrics['tasks_completed'] / max(1, self.metrics['tasks_submitted']) * 100
                )
            },
            'io_workers': io_stats,
            'cpu_workers': cpu_stats,
            'event_loop': {
                'is_running': asyncio.get_event_loop().is_running(),
                'is_closed': asyncio.get_event_loop().is_closed()
            }
        }
    
    async def optimize_performance(self):
        """Optimize runtime performance"""
        # Garbage collection optimization
        gc.collect()
        
        # Adjust worker pool sizes based on load
        if self.io_worker_pool:
            io_stats = self.io_worker_pool.get_stats()
            queue_size = io_stats['queue_size']
            active_workers = io_stats['active_workers']
            
            # Scale workers based on queue pressure
            if queue_size > active_workers * 10:
                # Consider adding more workers (implementation depends on requirements)
                pass
        
        # Memory optimization
        weakref_cleanup = weakref.WeakSet()
        for obj in gc.get_objects():
            if hasattr(obj, '__dict__'):
                weakref_cleanup.add(obj)
        
        # Force garbage collection of unreferenced objects
        gc.collect(2)  # Full collection
    
    async def shutdown(self, timeout: float = 30.0):
        """Graceful shutdown of async architecture"""
        print("Shutting down async architecture...")
        
        # Stop accepting new tasks
        self.shutdown_event.set()
        
        # Run cleanup tasks
        for cleanup_task in self.cleanup_tasks:
            try:
                await cleanup_task()
            except Exception as e:
                print(f"Cleanup task failed: {e}")
        
        # Stop components
        shutdown_tasks = []
        
        if self.scheduler:
            shutdown_tasks.append(self.scheduler.stop())
        
        if self.io_worker_pool:
            shutdown_tasks.append(self.io_worker_pool.stop(timeout))
        
        if self.cpu_worker_pool:
            shutdown_tasks.append(self.cpu_worker_pool.stop(timeout))
        
        if shutdown_tasks:
            await asyncio.gather(*shutdown_tasks, return_exceptions=True)
        
        print("Async architecture shutdown complete")
    
    def add_cleanup_task(self, cleanup_func: Callable[[], Awaitable[None]]):
        """Add cleanup task for shutdown"""
        self.cleanup_tasks.append(cleanup_func)

# Global async architecture instance
_async_architecture: Optional[AsyncArchitecture] = None

async def get_async_architecture(config: Dict[str, Any] = None) -> AsyncArchitecture:
    """Get or create global async architecture"""
    global _async_architecture
    
    if _async_architecture is None:
        _async_architecture = AsyncArchitecture(config)
        await _async_architecture.initialize()
    
    return _async_architecture

async def submit_async_task(coro: Awaitable[T], **kwargs) -> AsyncTask[T]:
    """Convenience function to submit async task"""
    arch = await get_async_architecture()
    return await arch.submit_task(coro, **kwargs)

# Decorators for easy async task creation
def async_task(priority: TaskPriority = TaskPriority.NORMAL,
               worker_type: WorkerType = WorkerType.IO_BOUND,
               timeout: Optional[float] = None,
               max_retries: int = 3):
    """Decorator to create async tasks"""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            arch = await get_async_architecture()
            coro = func(*args, **kwargs)
            return await arch.submit_task(
                coro=coro,
                priority=priority,
                worker_type=worker_type,
                timeout=timeout,
                max_retries=max_retries
            )
        return wrapper
    return decorator

def cpu_bound_task(priority: TaskPriority = TaskPriority.NORMAL):
    """Decorator for CPU-bound tasks"""
    return async_task(priority=priority, worker_type=WorkerType.CPU_BOUND)

def io_bound_task(priority: TaskPriority = TaskPriority.NORMAL):
    """Decorator for IO-bound tasks"""
    return async_task(priority=priority, worker_type=WorkerType.IO_BOUND)

# Export main classes and functions
__all__ = [
    'TaskPriority', 'WorkerType', 'AsyncTask', 'TaskQueue', 'WorkerPool',
    'AsyncScheduler', 'AsyncArchitecture', 'get_async_architecture',
    'submit_async_task', 'async_task', 'cpu_bound_task', 'io_bound_task'
]