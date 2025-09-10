"""
Comprehensive Resource Management System
Prevents memory leaks and ensures proper cleanup of async resources.
"""

import asyncio
import weakref
import gc
import threading
import psutil
import time
from typing import (
    Dict, List, Set, Optional, Any, Callable, TypeVar, Generic,
    Protocol, runtime_checkable, AsyncContextManager, ContextManager,
    Union, Type, Final
)
from typing_extensions import ParamSpec
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from abc import ABC, abstractmethod
import functools
import logging
from collections import defaultdict
import traceback
from contextlib import asynccontextmanager, contextmanager

from ..core.structured_logging import StructuredLogger
from ..core.type_system import typed, TypeSafetyLevel

T = TypeVar('T')
P = ParamSpec('P')


class ResourceType(Enum):
    """Types of managed resources."""
    DATABASE_CONNECTION = "database_connection"
    HTTP_CLIENT = "http_client"
    WEBSOCKET = "websocket"
    FILE_HANDLE = "file_handle"
    NETWORK_SOCKET = "network_socket"
    THREAD_POOL = "thread_pool"
    CACHE_INSTANCE = "cache_instance"
    LIGHTNING_CLIENT = "lightning_client"
    ASYNC_GENERATOR = "async_generator"
    EVENT_HANDLER = "event_handler"


class ResourceState(Enum):
    """Resource lifecycle states."""
    CREATED = "created"
    INITIALIZED = "initialized"
    ACTIVE = "active"
    IDLE = "idle"
    CLOSING = "closing"
    CLOSED = "closed"
    ERROR = "error"


@runtime_checkable
class ManagedResource(Protocol):
    """Protocol for resources that can be managed."""
    
    resource_id: str
    resource_type: ResourceType
    created_at: datetime
    
    async def close(self) -> None:
        """Close the resource."""
        ...
    
    def is_closed(self) -> bool:
        """Check if resource is closed."""
        ...
    
    def get_memory_usage(self) -> int:
        """Get memory usage in bytes."""
        ...


@runtime_checkable
class AsyncManagedResource(Protocol):
    """Protocol for async resources."""
    
    async def aclose(self) -> None:
        """Async close method."""
        ...
    
    async def __aenter__(self):
        """Async context manager entry."""
        ...
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        ...


@dataclass
class ResourceMetrics:
    """Resource usage metrics."""
    resource_id: str
    resource_type: ResourceType
    created_at: datetime
    last_accessed: datetime
    access_count: int = 0
    memory_usage_bytes: int = 0
    cpu_time_seconds: float = 0.0
    network_bytes_sent: int = 0
    network_bytes_received: int = 0
    error_count: int = 0
    state: ResourceState = ResourceState.CREATED


class MemoryMonitor:
    """Memory usage monitoring system."""
    
    def __init__(self, warning_threshold_mb: int = 512, critical_threshold_mb: int = 1024):
        self.warning_threshold = warning_threshold_mb * 1024 * 1024
        self.critical_threshold = critical_threshold_mb * 1024 * 1024
        self.logger = StructuredLogger("memory_monitor")
        self.process = psutil.Process()
        self.start_memory = self.get_memory_usage()
        self.peak_memory = self.start_memory
        self.measurements: List[tuple[datetime, int]] = []
        
    def get_memory_usage(self) -> int:
        """Get current memory usage in bytes."""
        try:
            memory_info = self.process.memory_info()
            return memory_info.rss  # Resident Set Size
        except Exception:
            return 0
    
    def record_measurement(self) -> None:
        """Record current memory measurement."""
        current_memory = self.get_memory_usage()
        now = datetime.now(timezone.utc)
        
        self.measurements.append((now, current_memory))
        
        # Keep only last 1000 measurements
        if len(self.measurements) > 1000:
            self.measurements = self.measurements[-1000:]
        
        # Update peak memory
        if current_memory > self.peak_memory:
            self.peak_memory = current_memory
        
        # Check thresholds
        if current_memory > self.critical_threshold:
            self.logger.critical("Memory usage critical", extra={
                'current_memory_mb': current_memory / 1024 / 1024,
                'threshold_mb': self.critical_threshold / 1024 / 1024
            })
        elif current_memory > self.warning_threshold:
            self.logger.warning("Memory usage warning", extra={
                'current_memory_mb': current_memory / 1024 / 1024,
                'threshold_mb': self.warning_threshold / 1024 / 1024
            })
    
    def get_memory_stats(self) -> Dict[str, Any]:
        """Get memory statistics."""
        current = self.get_memory_usage()
        
        return {
            'current_mb': current / 1024 / 1024,
            'start_mb': self.start_memory / 1024 / 1024,
            'peak_mb': self.peak_memory / 1024 / 1024,
            'increase_mb': (current - self.start_memory) / 1024 / 1024,
            'measurements_count': len(self.measurements),
            'warning_threshold_mb': self.warning_threshold / 1024 / 1024,
            'critical_threshold_mb': self.critical_threshold / 1024 / 1024
        }
    
    def detect_memory_leaks(self) -> List[Dict[str, Any]]:
        """Detect potential memory leaks."""
        if len(self.measurements) < 10:
            return []
        
        leaks = []
        recent_measurements = self.measurements[-10:]
        
        # Check for consistent growth
        growth_pattern = []
        for i in range(1, len(recent_measurements)):
            prev_memory = recent_measurements[i-1][1]
            curr_memory = recent_measurements[i][1]
            growth = curr_memory - prev_memory
            growth_pattern.append(growth)
        
        # If memory consistently grows, it's a potential leak
        positive_growth_count = sum(1 for g in growth_pattern if g > 0)
        if positive_growth_count >= 7:  # 70% of measurements show growth
            total_growth = sum(growth_pattern)
            leaks.append({
                'type': 'consistent_growth',
                'growth_mb': total_growth / 1024 / 1024,
                'severity': 'high' if total_growth > 50 * 1024 * 1024 else 'medium'
            })
        
        return leaks


class ResourceTracker:
    """Tracks all managed resources for leak detection."""
    
    def __init__(self):
        self.resources: Dict[str, ResourceMetrics] = {}
        self.resource_refs: Dict[str, weakref.ReferenceType] = {}
        self.lock = threading.RLock()
        self.logger = StructuredLogger("resource_tracker")
        self.memory_monitor = MemoryMonitor()
        
    def register_resource(self, resource: ManagedResource) -> None:
        """Register a resource for tracking."""
        with self.lock:
            metrics = ResourceMetrics(
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                created_at=resource.created_at,
                last_accessed=datetime.now(timezone.utc),
                state=ResourceState.CREATED
            )
            
            self.resources[resource.resource_id] = metrics
            
            # Create weak reference to detect when resource is garbage collected
            def cleanup_callback(ref):
                self._cleanup_resource(resource.resource_id)
            
            self.resource_refs[resource.resource_id] = weakref.ref(resource, cleanup_callback)
            
            self.logger.debug("Registered resource", extra={
                'resource_id': resource.resource_id,
                'resource_type': resource.resource_type.value
            })
    
    def unregister_resource(self, resource_id: str) -> None:
        """Unregister a resource."""
        with self.lock:
            if resource_id in self.resources:
                self.resources[resource_id].state = ResourceState.CLOSED
                self.logger.debug("Unregistered resource", extra={'resource_id': resource_id})
    
    def update_resource_state(self, resource_id: str, state: ResourceState) -> None:
        """Update resource state."""
        with self.lock:
            if resource_id in self.resources:
                self.resources[resource_id].state = state
                self.resources[resource_id].last_accessed = datetime.now(timezone.utc)
    
    def record_resource_access(self, resource_id: str, memory_delta: int = 0) -> None:
        """Record resource access."""
        with self.lock:
            if resource_id in self.resources:
                metrics = self.resources[resource_id]
                metrics.access_count += 1
                metrics.last_accessed = datetime.now(timezone.utc)
                metrics.memory_usage_bytes += memory_delta
                
                if metrics.state == ResourceState.CREATED:
                    metrics.state = ResourceState.ACTIVE
    
    def record_resource_error(self, resource_id: str, error: Exception) -> None:
        """Record resource error."""
        with self.lock:
            if resource_id in self.resources:
                self.resources[resource_id].error_count += 1
                self.resources[resource_id].state = ResourceState.ERROR
                
                self.logger.error("Resource error", extra={
                    'resource_id': resource_id,
                    'error': str(error),
                    'traceback': traceback.format_exc()
                })
    
    def _cleanup_resource(self, resource_id: str) -> None:
        """Cleanup resource after garbage collection."""
        with self.lock:
            if resource_id in self.resource_refs:
                del self.resource_refs[resource_id]
            
            if resource_id in self.resources:
                metrics = self.resources[resource_id]
                if metrics.state not in [ResourceState.CLOSED, ResourceState.ERROR]:
                    self.logger.warning("Resource garbage collected without proper cleanup", extra={
                        'resource_id': resource_id,
                        'resource_type': metrics.resource_type.value,
                        'state': metrics.state.value
                    })
    
    def get_resource_stats(self) -> Dict[str, Any]:
        """Get comprehensive resource statistics."""
        with self.lock:
            stats = {
                'total_resources': len(self.resources),
                'by_type': defaultdict(int),
                'by_state': defaultdict(int),
                'memory_stats': self.memory_monitor.get_memory_stats(),
                'potential_leaks': []
            }
            
            active_resources = []
            old_resources = []
            now = datetime.now(timezone.utc)
            
            for resource_id, metrics in self.resources.items():
                stats['by_type'][metrics.resource_type.value] += 1
                stats['by_state'][metrics.state.value] += 1
                
                # Check for old active resources
                age = now - metrics.created_at
                if metrics.state == ResourceState.ACTIVE and age > timedelta(hours=1):
                    old_resources.append({
                        'resource_id': resource_id,
                        'type': metrics.resource_type.value,
                        'age_minutes': age.total_seconds() / 60,
                        'access_count': metrics.access_count
                    })
                
                if metrics.state in [ResourceState.ACTIVE, ResourceState.IDLE]:
                    active_resources.append(resource_id)
            
            stats['active_resources'] = len(active_resources)
            stats['old_resources'] = old_resources
            stats['potential_leaks'].extend(self.memory_monitor.detect_memory_leaks())
            
            return dict(stats)
    
    def force_cleanup_old_resources(self, max_age_hours: int = 2) -> int:
        """Force cleanup of old resources."""
        cleanup_count = 0
        now = datetime.now(timezone.utc)
        
        with self.lock:
            for resource_id, metrics in list(self.resources.items()):
                age = now - metrics.created_at
                
                if age > timedelta(hours=max_age_hours) and metrics.state != ResourceState.CLOSED:
                    # Try to get the actual resource and close it
                    if resource_id in self.resource_refs:
                        resource_ref = self.resource_refs[resource_id]
                        resource = resource_ref()
                        
                        if resource is not None:
                            try:
                                if hasattr(resource, 'close'):
                                    if asyncio.iscoroutinefunction(resource.close):
                                        # Schedule async cleanup
                                        asyncio.create_task(resource.close())
                                    else:
                                        resource.close()
                                elif hasattr(resource, 'aclose'):
                                    asyncio.create_task(resource.aclose())
                                    
                                cleanup_count += 1
                                self.logger.info("Force cleaned old resource", extra={
                                    'resource_id': resource_id,
                                    'age_hours': age.total_seconds() / 3600
                                })
                                
                            except Exception as e:
                                self.logger.error("Error during force cleanup", extra={
                                    'resource_id': resource_id,
                                    'error': str(e)
                                })
                    
                    # Mark as closed
                    metrics.state = ResourceState.CLOSED
        
        return cleanup_count


class ResourcePool(Generic[T]):
    """Generic resource pool with lifecycle management."""
    
    def __init__(self, resource_factory: Callable[[], T], 
                 min_size: int = 1, max_size: int = 10,
                 max_age_seconds: int = 3600,
                 resource_type: ResourceType = ResourceType.CACHE_INSTANCE):
        self.resource_factory = resource_factory
        self.min_size = min_size
        self.max_size = max_size
        self.max_age_seconds = max_age_seconds
        self.resource_type = resource_type
        
        self.available: List[T] = []
        self.in_use: Set[T] = set()
        self.created_times: Dict[T, datetime] = {}
        self.lock = asyncio.Lock()
        self.tracker = get_resource_tracker()
        self.logger = StructuredLogger("resource_pool")
        
    async def acquire(self) -> T:
        """Acquire a resource from the pool."""
        async with self.lock:
            # Remove expired resources
            await self._cleanup_expired_resources()
            
            # Get available resource or create new one
            if self.available:
                resource = self.available.pop()
            elif len(self.in_use) < self.max_size:
                resource = await self._create_resource()
            else:
                # Wait for a resource to become available
                # This is a simplified implementation
                raise Exception("Resource pool exhausted")
            
            self.in_use.add(resource)
            return resource
    
    async def release(self, resource: T) -> None:
        """Release a resource back to the pool."""
        async with self.lock:
            if resource in self.in_use:
                self.in_use.remove(resource)
                
                # Check if resource is still valid
                if await self._is_resource_valid(resource):
                    self.available.append(resource)
                else:
                    await self._destroy_resource(resource)
    
    async def _create_resource(self) -> T:
        """Create a new resource."""
        try:
            resource = self.resource_factory()
            self.created_times[resource] = datetime.now(timezone.utc)
            
            # Register with tracker if it's a managed resource
            if isinstance(resource, ManagedResource):
                self.tracker.register_resource(resource)
            
            self.logger.debug("Created pool resource", extra={'pool_size': len(self.available) + len(self.in_use)})
            return resource
            
        except Exception as e:
            self.logger.error("Failed to create resource", extra={'error': str(e)})
            raise
    
    async def _destroy_resource(self, resource: T) -> None:
        """Destroy a resource."""
        try:
            if hasattr(resource, 'close'):
                if asyncio.iscoroutinefunction(resource.close):
                    await resource.close()
                else:
                    resource.close()
            elif hasattr(resource, 'aclose'):
                await resource.aclose()
            
            if resource in self.created_times:
                del self.created_times[resource]
            
            if isinstance(resource, ManagedResource):
                self.tracker.unregister_resource(resource.resource_id)
                
        except Exception as e:
            self.logger.error("Error destroying resource", extra={'error': str(e)})
    
    async def _is_resource_valid(self, resource: T) -> bool:
        """Check if resource is still valid."""
        try:
            # Check age
            if resource in self.created_times:
                age = datetime.now(timezone.utc) - self.created_times[resource]
                if age.total_seconds() > self.max_age_seconds:
                    return False
            
            # Check if resource is closed
            if hasattr(resource, 'is_closed'):
                return not resource.is_closed()
            
            return True
            
        except Exception:
            return False
    
    async def _cleanup_expired_resources(self) -> None:
        """Clean up expired resources."""
        expired = []
        
        for resource in self.available[:]:
            if not await self._is_resource_valid(resource):
                expired.append(resource)
        
        for resource in expired:
            self.available.remove(resource)
            await self._destroy_resource(resource)
    
    async def close(self) -> None:
        """Close the resource pool."""
        async with self.lock:
            # Close all resources
            all_resources = self.available + list(self.in_use)
            
            for resource in all_resources:
                await self._destroy_resource(resource)
            
            self.available.clear()
            self.in_use.clear()
            self.created_times.clear()
            
            self.logger.info("Resource pool closed")


def auto_cleanup(timeout_seconds: int = 300):
    """Decorator to automatically cleanup resources after timeout."""
    
    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @functools.wraps(func)
        async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            start_time = time.time()
            
            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                elapsed = time.time() - start_time
                if elapsed > timeout_seconds:
                    # Force garbage collection
                    gc.collect()
                    
                    # Log potential resource leak
                    logger = StructuredLogger("auto_cleanup")
                    logger.warning("Long-running function detected", extra={
                        'function': func.__name__,
                        'elapsed_seconds': elapsed,
                        'timeout_seconds': timeout_seconds
                    })
        
        @functools.wraps(func)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                elapsed = time.time() - start_time
                if elapsed > timeout_seconds:
                    gc.collect()
                    
                    logger = StructuredLogger("auto_cleanup")
                    logger.warning("Long-running function detected", extra={
                        'function': func.__name__,
                        'elapsed_seconds': elapsed
                    })
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    
    return decorator


@asynccontextmanager
async def managed_resource(resource: T) -> T:
    """Async context manager for automatic resource cleanup."""
    tracker = get_resource_tracker()
    
    try:
        if isinstance(resource, ManagedResource):
            tracker.register_resource(resource)
            tracker.update_resource_state(resource.resource_id, ResourceState.ACTIVE)
        
        yield resource
        
    except Exception as e:
        if isinstance(resource, ManagedResource):
            tracker.record_resource_error(resource.resource_id, e)
        raise
        
    finally:
        try:
            if hasattr(resource, 'close'):
                if asyncio.iscoroutinefunction(resource.close):
                    await resource.close()
                else:
                    resource.close()
            elif hasattr(resource, 'aclose'):
                await resource.aclose()
                
            if isinstance(resource, ManagedResource):
                tracker.unregister_resource(resource.resource_id)
                
        except Exception as e:
            logger = StructuredLogger("managed_resource")
            logger.error("Error during resource cleanup", extra={'error': str(e)})


class ResourceManager:
    """Central resource manager for the application."""
    
    def __init__(self):
        self.tracker = ResourceTracker()
        self.pools: Dict[str, ResourcePool] = {}
        self.cleanup_task: Optional[asyncio.Task] = None
        self.logger = StructuredLogger("resource_manager")
        
    async def start(self) -> None:
        """Start the resource manager."""
        self.cleanup_task = asyncio.create_task(self._periodic_cleanup())
        self.logger.info("Resource manager started")
    
    async def stop(self) -> None:
        """Stop the resource manager."""
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Close all pools
        for pool in self.pools.values():
            await pool.close()
        
        self.pools.clear()
        self.logger.info("Resource manager stopped")
    
    async def _periodic_cleanup(self) -> None:
        """Periodic cleanup task."""
        while True:
            try:
                await asyncio.sleep(300)  # Every 5 minutes
                
                # Record memory measurement
                self.tracker.memory_monitor.record_measurement()
                
                # Force cleanup old resources
                cleanup_count = self.tracker.force_cleanup_old_resources()
                
                if cleanup_count > 0:
                    self.logger.info("Cleaned up old resources", extra={'count': cleanup_count})
                
                # Force garbage collection if memory usage is high
                memory_stats = self.tracker.memory_monitor.get_memory_stats()
                if memory_stats['current_mb'] > 500:  # 500MB threshold
                    gc.collect()
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("Error in periodic cleanup", extra={'error': str(e)})
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive resource management statistics."""
        return {
            'resource_tracker': self.tracker.get_resource_stats(),
            'pools': {name: len(pool.available) + len(pool.in_use) 
                     for name, pool in self.pools.items()},
            'cleanup_task_running': self.cleanup_task is not None and not self.cleanup_task.done()
        }
    
    def create_pool(self, name: str, resource_factory: Callable[[], T],
                   **kwargs) -> ResourcePool[T]:
        """Create a new resource pool."""
        pool = ResourcePool(resource_factory, **kwargs)
        self.pools[name] = pool
        return pool
    
    def get_pool(self, name: str) -> Optional[ResourcePool]:
        """Get a resource pool by name."""
        return self.pools.get(name)


# Global resource manager instance
_resource_manager: Optional[ResourceManager] = None
_resource_tracker: Optional[ResourceTracker] = None


def get_resource_manager() -> ResourceManager:
    """Get global resource manager instance."""
    global _resource_manager
    if _resource_manager is None:
        _resource_manager = ResourceManager()
    return _resource_manager


def get_resource_tracker() -> ResourceTracker:
    """Get global resource tracker instance."""
    global _resource_tracker
    if _resource_tracker is None:
        _resource_tracker = ResourceTracker()
    return _resource_tracker


async def initialize_resource_management() -> None:
    """Initialize global resource management."""
    manager = get_resource_manager()
    await manager.start()


async def shutdown_resource_management() -> None:
    """Shutdown global resource management."""
    manager = get_resource_manager()
    await manager.stop()