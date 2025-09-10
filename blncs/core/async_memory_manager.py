#!/usr/bin/env python3
"""
Comprehensive async memory management system for BLNCS
Prevents memory leaks in Lightning Network operations through systematic tracking and cleanup
"""

import asyncio
import weakref
import gc
import tracemalloc
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    # Mock psutil for systems without it
    class MockProcess:
        def memory_info(self):
            return type('obj', (object,), {'rss': 100 * 1024 * 1024})()
    
    class MockPsutil:
        def cpu_percent(self, interval=None):
            return 50.0
        def virtual_memory(self):
            return type('obj', (object,), {'percent': 50.0, 'available': 1024 * 1024 * 1024})()
        def Process(self):
            return MockProcess()
    
    psutil = MockPsutil()
from typing import Dict, List, Set, Optional, Any, Callable, Awaitable, AsyncContextManager
from dataclasses import dataclass, field
from enum import Enum
from contextlib import asynccontextmanager
from collections import defaultdict
import time
import threading
from concurrent.futures import ThreadPoolExecutor
import logging

logger = logging.getLogger(__name__)

class MemoryLeakSeverity(Enum):
    """Memory leak severity levels"""
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"
    CRITICAL = "critical"

class TaskState(Enum):
    """Async task states for tracking"""
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"

@dataclass
class AsyncTaskInfo:
    """Information about tracked async tasks"""
    task_id: str
    name: str
    state: TaskState
    created_at: float
    memory_snapshot: int
    stack_trace: str
    cleanup_callbacks: List[Callable] = field(default_factory=list)
    resource_refs: Set[Any] = field(default_factory=set)

@dataclass
class MemoryLeakReport:
    """Memory leak detection report"""
    severity: MemoryLeakSeverity
    leaked_tasks: List[str]
    leaked_memory_mb: float
    growth_rate_mb_per_sec: float
    recommendations: List[str]
    timestamp: float

class AsyncResourceTracker:
    """Tracks async resources and prevents leaks"""
    
    def __init__(self):
        self._tasks: Dict[str, AsyncTaskInfo] = {}
        self._task_counter = 0
        self._lock = threading.RLock()
        self._cleanup_callbacks: Dict[str, List[Callable]] = defaultdict(list)
        self._memory_snapshots: List[tuple] = []
        self._leak_threshold_mb = 50.0
        self._monitoring_enabled = True
        self._cleanup_interval = 30.0
        
        # Start background monitoring
        self._monitor_task = None
        self._start_monitoring()
    
    def _start_monitoring(self):
        """Start background memory monitoring"""
        if not tracemalloc.is_tracing():
            tracemalloc.start(10)  # Keep 10 frames
        
        loop = None
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            pass
        
        if loop and not self._monitor_task:
            self._monitor_task = loop.create_task(self._memory_monitor())
    
    async def _memory_monitor(self):
        """Background memory monitoring task"""
        while self._monitoring_enabled:
            try:
                await self._check_memory_leaks()
                await asyncio.sleep(self._cleanup_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Memory monitor error: {e}")
                await asyncio.sleep(5.0)
    
    def register_task(self, task: asyncio.Task, name: str = None) -> str:
        """Register async task for tracking"""
        task_id = f"task_{self._task_counter}"
        self._task_counter += 1
        
        if not name:
            name = getattr(task, '__name__', f'anonymous_task_{task_id}')
        
        # Get current memory usage
        process = psutil.Process()
        memory_mb = process.memory_info().rss / 1024 / 1024
        
        # Get stack trace
        stack_trace = ''.join(traceback.format_stack())
        
        task_info = AsyncTaskInfo(
            task_id=task_id,
            name=name,
            state=TaskState.CREATED,
            created_at=time.time(),
            memory_snapshot=memory_mb,
            stack_trace=stack_trace
        )
        
        with self._lock:
            self._tasks[task_id] = task_info
        
        # Add task completion callback
        task.add_done_callback(lambda t: self._on_task_complete(task_id, t))
        
        return task_id
    
    def _on_task_complete(self, task_id: str, task: asyncio.Task):
        """Handle task completion"""
        with self._lock:
            if task_id in self._tasks:
                task_info = self._tasks[task_id]
                
                if task.cancelled():
                    task_info.state = TaskState.CANCELLED
                elif task.exception():
                    task_info.state = TaskState.FAILED
                else:
                    task_info.state = TaskState.COMPLETED
                
                # Execute cleanup callbacks
                for callback in task_info.cleanup_callbacks:
                    try:
                        if asyncio.iscoroutinefunction(callback):
                            # Schedule coroutine for later execution
                            loop = asyncio.get_event_loop()
                            loop.create_task(callback())
                        else:
                            callback()
                    except Exception as e:
                        logger.error(f"Cleanup callback error for task {task_id}: {e}")
                
                # Clean up resource references
                task_info.resource_refs.clear()
    
    def add_cleanup_callback(self, task_id: str, callback: Callable):
        """Add cleanup callback for task"""
        with self._lock:
            if task_id in self._tasks:
                self._tasks[task_id].cleanup_callbacks.append(callback)
    
    def track_resource(self, task_id: str, resource: Any):
        """Track resource for cleanup"""
        with self._lock:
            if task_id in self._tasks:
                # Use weak reference to avoid circular references
                try:
                    weak_ref = weakref.ref(resource)
                    self._tasks[task_id].resource_refs.add(weak_ref)
                except TypeError:
                    # Some objects can't be weak referenced
                    logger.warning(f"Cannot weak reference resource: {type(resource)}")
    
    async def _check_memory_leaks(self) -> Optional[MemoryLeakReport]:
        """Check for memory leaks in tracked tasks"""
        process = psutil.Process()
        current_memory_mb = process.memory_info().rss / 1024 / 1024
        current_time = time.time()
        
        # Store memory snapshot
        self._memory_snapshots.append((current_time, current_memory_mb))
        
        # Keep only recent snapshots (last 10 minutes)
        cutoff_time = current_time - 600
        self._memory_snapshots = [
            (t, m) for t, m in self._memory_snapshots 
            if t > cutoff_time
        ]
        
        # Check for memory growth
        if len(self._memory_snapshots) < 3:
            return None
        
        # Calculate memory growth rate
        oldest_time, oldest_memory = self._memory_snapshots[0]
        growth_mb = current_memory_mb - oldest_memory
        time_delta = current_time - oldest_time
        growth_rate = growth_mb / time_delta if time_delta > 0 else 0
        
        # Identify leaked tasks
        leaked_tasks = []
        with self._lock:
            for task_id, task_info in self._tasks.items():
                # Task running for more than 5 minutes might be leaked
                if (task_info.state == TaskState.RUNNING and 
                    current_time - task_info.created_at > 300):
                    leaked_tasks.append(task_id)
        
        # Determine severity
        severity = MemoryLeakSeverity.LOW
        if growth_mb > self._leak_threshold_mb:
            if growth_rate > 5.0:  # 5 MB/sec growth
                severity = MemoryLeakSeverity.CRITICAL
            elif growth_rate > 1.0:  # 1 MB/sec growth
                severity = MemoryLeakSeverity.HIGH
            else:
                severity = MemoryLeakSeverity.MEDIUM
        
        # Generate recommendations
        recommendations = []
        if leaked_tasks:
            recommendations.append(f"Cancel {len(leaked_tasks)} long-running tasks")
        if growth_rate > 1.0:
            recommendations.append("Investigate memory growth in recent operations")
        if current_memory_mb > 500:
            recommendations.append("Consider garbage collection")
        
        leak_report = MemoryLeakReport(
            severity=severity,
            leaked_tasks=leaked_tasks,
            leaked_memory_mb=growth_mb,
            growth_rate_mb_per_sec=growth_rate,
            recommendations=recommendations,
            timestamp=current_time
        )
        
        # Log significant leaks
        if severity in [MemoryLeakSeverity.HIGH, MemoryLeakSeverity.CRITICAL]:
            logger.warning(f"Memory leak detected: {leak_report}")
            
            # Auto-cleanup critical leaks
            if severity == MemoryLeakSeverity.CRITICAL:
                await self.emergency_cleanup()
        
        return leak_report
    
    async def emergency_cleanup(self):
        """Emergency cleanup of resources"""
        logger.warning("Executing emergency memory cleanup")
        
        # Cancel long-running tasks
        current_time = time.time()
        with self._lock:
            for task_id, task_info in list(self._tasks.items()):
                if (task_info.state == TaskState.RUNNING and 
                    current_time - task_info.created_at > 300):
                    
                    logger.warning(f"Cancelling long-running task: {task_id}")
                    # Find and cancel the actual task
                    for task in asyncio.all_tasks():
                        if hasattr(task, '_blncs_task_id') and task._blncs_task_id == task_id:
                            task.cancel()
        
        # Force garbage collection
        gc.collect()
        
        # Clear old task records
        self._cleanup_completed_tasks()
    
    def _cleanup_completed_tasks(self):
        """Clean up completed task records"""
        current_time = time.time()
        cutoff_time = current_time - 3600  # Keep records for 1 hour
        
        with self._lock:
            to_remove = []
            for task_id, task_info in self._tasks.items():
                if (task_info.state in [TaskState.COMPLETED, TaskState.CANCELLED, TaskState.FAILED] and
                    task_info.created_at < cutoff_time):
                    to_remove.append(task_id)
            
            for task_id in to_remove:
                del self._tasks[task_id]
        
        logger.debug(f"Cleaned up {len(to_remove)} completed task records")
    
    def get_memory_stats(self) -> Dict[str, Any]:
        """Get current memory statistics"""
        process = psutil.Process()
        memory_info = process.memory_info()
        
        with self._lock:
            task_counts = {
                'created': sum(1 for t in self._tasks.values() if t.state == TaskState.CREATED),
                'running': sum(1 for t in self._tasks.values() if t.state == TaskState.RUNNING),
                'completed': sum(1 for t in self._tasks.values() if t.state == TaskState.COMPLETED),
                'cancelled': sum(1 for t in self._tasks.values() if t.state == TaskState.CANCELLED),
                'failed': sum(1 for t in self._tasks.values() if t.state == TaskState.FAILED)
            }
        
        return {
            'memory_mb': memory_info.rss / 1024 / 1024,
            'memory_peak_mb': memory_info.peak_wset / 1024 / 1024 if hasattr(memory_info, 'peak_wset') else None,
            'task_counts': task_counts,
            'total_tasks_tracked': len(self._tasks),
            'monitoring_enabled': self._monitoring_enabled
        }
    
    async def shutdown(self):
        """Shutdown resource tracker"""
        self._monitoring_enabled = False
        
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        
        # Final cleanup
        await self.emergency_cleanup()

class AsyncContextTracker:
    """Tracks async context managers to ensure proper cleanup"""
    
    def __init__(self):
        self._contexts: Dict[str, AsyncContextManager] = {}
        self._context_counter = 0
        self._lock = threading.RLock()
    
    @asynccontextmanager
    async def tracked_context(self, context_manager: AsyncContextManager, name: str = None):
        """Track async context manager"""
        context_id = f"ctx_{self._context_counter}"
        self._context_counter += 1
        
        if not name:
            name = f"anonymous_context_{context_id}"
        
        with self._lock:
            self._contexts[context_id] = context_manager
        
        try:
            async with context_manager as ctx:
                yield ctx
        finally:
            with self._lock:
                self._contexts.pop(context_id, None)
    
    async def cleanup_all(self):
        """Force cleanup of all tracked contexts"""
        with self._lock:
            contexts = list(self._contexts.items())
        
        for context_id, context in contexts:
            try:
                if hasattr(context, '__aexit__'):
                    await context.__aexit__(None, None, None)
                logger.debug(f"Force cleaned context: {context_id}")
            except Exception as e:
                logger.error(f"Error cleaning context {context_id}: {e}")

# Global instances
_async_resource_tracker = None
_async_context_tracker = None

def get_async_resource_tracker() -> AsyncResourceTracker:
    """Get global async resource tracker"""
    global _async_resource_tracker
    if _async_resource_tracker is None:
        _async_resource_tracker = AsyncResourceTracker()
    return _async_resource_tracker

def get_async_context_tracker() -> AsyncContextTracker:
    """Get global async context tracker"""
    global _async_context_tracker
    if _async_context_tracker is None:
        _async_context_tracker = AsyncContextTracker()
    return _async_context_tracker

# Decorator for automatic task tracking
def track_async_task(name: str = None):
    """Decorator to automatically track async tasks"""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            tracker = get_async_resource_tracker()
            
            # Create task for the function
            task = asyncio.create_task(func(*args, **kwargs))
            task_name = name or func.__name__
            
            # Register task
            task_id = tracker.register_task(task, task_name)
            task._blncs_task_id = task_id
            
            return await task
        return wrapper
    return decorator

# Context manager for Lightning Network operations
@asynccontextmanager
async def lightning_operation_context(operation_name: str):
    """Context manager for Lightning Network operations with memory tracking"""
    tracker = get_async_resource_tracker()
    context_tracker = get_async_context_tracker()
    
    # Track memory before operation
    process = psutil.Process()
    initial_memory = process.memory_info().rss / 1024 / 1024
    
    logger.debug(f"Starting Lightning operation: {operation_name} (Memory: {initial_memory:.1f} MB)")
    
    try:
        yield tracker
    finally:
        # Check memory after operation
        final_memory = process.memory_info().rss / 1024 / 1024
        memory_delta = final_memory - initial_memory
        
        if memory_delta > 10.0:  # More than 10MB growth
            logger.warning(f"High memory growth in {operation_name}: {memory_delta:.1f} MB")
        
        logger.debug(f"Completed Lightning operation: {operation_name} (Memory delta: {memory_delta:+.1f} MB)")

# Async cleanup utilities
async def safe_task_cleanup(tasks: List[asyncio.Task], timeout: float = 10.0):
    """Safely cleanup list of async tasks"""
    if not tasks:
        return
    
    # Cancel all tasks
    for task in tasks:
        if not task.done():
            task.cancel()
    
    # Wait for cancellation with timeout
    try:
        await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=timeout
        )
    except asyncio.TimeoutError:
        logger.warning(f"Timeout waiting for {len(tasks)} tasks to cleanup")
    
    logger.debug(f"Cleaned up {len(tasks)} async tasks")

async def safe_coroutine_cleanup(coros: List[Awaitable], timeout: float = 5.0):
    """Safely cleanup list of coroutines"""
    if not coros:
        return
    
    tasks = [asyncio.create_task(coro) for coro in coros]
    await safe_task_cleanup(tasks, timeout)

# Memory-efficient async utilities
class AsyncBoundedSemaphore:
    """Bounded semaphore with memory tracking"""
    
    def __init__(self, value: int = 100):
        self._semaphore = asyncio.BoundedSemaphore(value)
        self._active_count = 0
        self._max_memory_per_operation = 50.0  # MB
    
    async def acquire(self, operation_name: str = "unknown"):
        """Acquire semaphore with memory check"""
        # Check current memory usage
        process = psutil.Process()
        current_memory = process.memory_info().rss / 1024 / 1024
        
        # Estimate if we have enough memory for another operation
        estimated_total = current_memory + (self._active_count * self._max_memory_per_operation)
        
        if estimated_total > 1000:  # 1GB limit
            raise MemoryError(f"Insufficient memory for operation: {operation_name}")
        
        await self._semaphore.acquire()
        self._active_count += 1
    
    def release(self):
        """Release semaphore"""
        self._semaphore.release()
        self._active_count = max(0, self._active_count - 1)

# Export main classes and functions
__all__ = [
    'AsyncResourceTracker',
    'AsyncContextTracker', 
    'MemoryLeakReport',
    'MemoryLeakSeverity',
    'get_async_resource_tracker',
    'get_async_context_tracker',
    'track_async_task',
    'lightning_operation_context',
    'safe_task_cleanup',
    'safe_coroutine_cleanup',
    'AsyncBoundedSemaphore'
]